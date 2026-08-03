//go:build windows

package virtio

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"unicode/utf8"
	"unsafe"

	"github.com/hanwen/go-fuse/v2/fuse"
	"golang.org/x/sys/windows"
)

// winFileID is the NTFS identity used as the guest inode identity.
type winFileID struct {
	volume uint32
	index  uint64
}

type winFileInfo struct {
	attr    fuse.Attr
	attrs   uint32
	id      winFileID
	dir     bool
	reparse bool
}

// winExportFS is the native Windows passthrough backend. It keeps the export
// root open and resolves guest paths relative to open parent handles with
// NtCreateFile. Host path strings are used only to open the initial root and
// for directory enumeration/metadata calls that Windows exposes by path.
type winExportFS struct {
	root windows.Handle
	path string
	salt uint64

	mu       sync.RWMutex
	closed   bool
	renameMu sync.Mutex
}

const (
	winShareMode      = windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE
	winBaseOpenOpts   = windows.FILE_OPEN_FOR_BACKUP_INTENT | windows.FILE_OPEN_REPARSE_POINT | windows.FILE_SYNCHRONOUS_IO_NONALERT
	winMetadataAccess = windows.FILE_GENERIC_READ
	winFileCreated    = 2 // IO_STATUS_BLOCK Information for NtCreateFile
)

func newWinExportFS(rootPath string, salt uint64) (*winExportFS, error) {
	clean, err := canonicalWinSharePath(rootPath)
	if err != nil {
		return nil, err
	}
	root, err := openWinRoot(clean)
	if err != nil {
		return nil, fmt.Errorf("open share root: %w", err)
	}
	info, err := winInfoFromHandle(root, salt)
	if err != nil {
		_ = windows.CloseHandle(root)
		return nil, fmt.Errorf("stat share root: %w", err)
	}
	if !info.dir {
		_ = windows.CloseHandle(root)
		return nil, fmt.Errorf("share root is not a directory: %s", clean)
	}
	if info.reparse {
		_ = windows.CloseHandle(root)
		return nil, fmt.Errorf("share root may not be a reparse point: %s", clean)
	}
	if err := requireWinNTFS(root); err != nil {
		_ = windows.CloseHandle(root)
		return nil, err
	}
	return &winExportFS{root: root, path: clean, salt: salt}, nil
}

func (b *winExportFS) Close() error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.root == 0 {
		return nil
	}
	err := windows.CloseHandle(b.root)
	b.root = 0
	b.closed = true
	return err
}

func canonicalWinSharePath(p string) (string, error) {
	if p == "" {
		return "", fmt.Errorf("share path is empty")
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	if strings.HasPrefix(abs, `\?\UNC\`) {
		return "", fmt.Errorf("UNC/network share roots are not supported: %s", p)
	}
	if strings.HasPrefix(abs, `\\?\`) {
		abs = strings.TrimPrefix(abs, `\\?\`)
	}
	if strings.HasPrefix(abs, `\\`) {
		return "", fmt.Errorf("UNC/network share roots are not supported: %s", p)
	}
	if filepath.VolumeName(abs) == "" {
		return "", fmt.Errorf("share path must include a drive: %s", p)
	}
	var attrData windows.Win32FileAttributeData
	if err := windows.GetFileAttributesEx(windows.StringToUTF16Ptr(abs),
		windows.GetFileExInfoStandard, (*byte)(unsafe.Pointer(&attrData))); err != nil {
		return "", err
	}
	if attrData.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return "", fmt.Errorf("share root may not be a reparse point: %s", p)
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", err
	}
	if strings.HasPrefix(resolved, `\?\UNC\`) {
		return "", fmt.Errorf("UNC/network share roots are not supported: %s", p)
	}
	if strings.HasPrefix(resolved, `\\?\`) {
		resolved = strings.TrimPrefix(resolved, `\\?\`)
	}
	if strings.HasPrefix(resolved, `\??\`) {
		resolved = strings.TrimPrefix(resolved, `\??\`)
	}
	if strings.HasPrefix(resolved, `\\`) {
		return "", fmt.Errorf("UNC/network share roots are not supported: %s", p)
	}
	return filepath.Clean(resolved), nil
}

func openWinRoot(p string) (windows.Handle, error) {
	name := p
	if strings.HasPrefix(name, `\\?\`) {
		name = strings.TrimPrefix(name, `\\?\`)
	}
	if strings.HasPrefix(name, `\??\`) {
		name = strings.TrimPrefix(name, `\??\`)
	}
	ntName, err := windows.NewNTUnicodeString(`\??\` + name)
	if err != nil {
		return 0, err
	}
	oa := windows.OBJECT_ATTRIBUTES{
		Length:     uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})),
		ObjectName: ntName,
		Attributes: 0, // case-sensitive lookup semantics for the Linux guest
	}
	var iosb windows.IO_STATUS_BLOCK
	var h windows.Handle
	err = windows.NtCreateFile(&h,
		windows.FILE_GENERIC_READ,
		&oa, &iosb, nil, windows.FILE_ATTRIBUTE_NORMAL, winShareMode,
		windows.FILE_OPEN,
		winBaseOpenOpts|windows.FILE_DIRECTORY_FILE,
		0, 0)
	if err != nil {
		return 0, err
	}
	return h, nil
}

func requireWinNTFS(root windows.Handle) error {
	var volumeName [64]uint16
	var fsName [32]uint16
	var serial, maxComponent, flags uint32
	err := windows.GetVolumeInformationByHandle(root,
		&volumeName[0], uint32(len(volumeName)),
		&serial, &maxComponent, &flags,
		&fsName[0], uint32(len(fsName)))
	if err != nil {
		return fmt.Errorf("query share volume: %w", err)
	}
	if !strings.EqualFold(windows.UTF16ToString(fsName[:]), "NTFS") {
		return fmt.Errorf("share root must be on NTFS (got %s)", windows.UTF16ToString(fsName[:]))
	}
	return nil
}

func duplicateWinHandle(h windows.Handle) (windows.Handle, error) {
	var out windows.Handle
	err := windows.DuplicateHandle(windows.CurrentProcess(), h,
		windows.CurrentProcess(), &out, 0, false, windows.DUPLICATE_SAME_ACCESS)
	return out, err
}

func ntStatusErrno(err error) syscall.Errno {
	if err == nil {
		return 0
	}
	var st windows.NTStatus
	if errors.As(err, &st) {
		var status fuse.Status
		switch st {
		case windows.STATUS_OBJECT_NAME_NOT_FOUND, windows.STATUS_OBJECT_PATH_NOT_FOUND:
			status = fuse.ENOENT
		case windows.STATUS_OBJECT_NAME_COLLISION:
			status = fuse.EEXIST
		case windows.STATUS_ACCESS_DENIED:
			status = fuse.EACCES
		case windows.STATUS_PRIVILEGE_NOT_HELD:
			status = fuse.EPERM
		case windows.STATUS_SHARING_VIOLATION:
			status = fuse.EBUSY
		case windows.STATUS_DISK_FULL:
			status = fuse.ENOSPC
		case windows.STATUS_OBJECT_NAME_INVALID:
			status = fuse.EINVAL
		case windows.STATUS_NOT_A_DIRECTORY:
			status = fuse.ENOTDIR
		case windows.STATUS_FILE_IS_A_DIRECTORY:
			status = fuse.EISDIR
		case windows.STATUS_DIRECTORY_NOT_EMPTY:
			status = fuse.ENOTEMPTY
		default:
			status = fuse.ToStatus(st.Errno())
		}
		return fuse.ErrnoFromStatus(status)
	}
	return fuse.ErrnoFromStatus(fuse.ToStatus(err))
}

func linuxErrno(status fuse.Status) syscall.Errno { return fuse.ErrnoFromStatus(status) }

func validWinGuestName(name string) bool {
	if name == "" || name == "." || name == ".." || !utf8.ValidString(name) || strings.ContainsAny(name, "/\\\x00:") {
		return false
	}
	if strings.HasSuffix(name, " ") || strings.HasSuffix(name, ".") {
		return false
	}
	base := strings.ToUpper(name)
	if i := strings.IndexByte(base, '.'); i >= 0 {
		base = base[:i]
	}
	switch base {
	case "CON", "PRN", "AUX", "NUL":
		return false
	}
	if len(base) == 4 {
		if (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && base[3] >= '1' && base[3] <= '9' {
			return false
		}
	}
	return true
}

func (b *winExportFS) ntOpen(parent windows.Handle, name string, access, disposition, options uint32) (windows.Handle, error) {
	h, _, err := b.ntOpenInfo(parent, name, access, disposition, options)
	return h, err
}

func (b *winExportFS) ntOpenInfo(parent windows.Handle, name string, access, disposition, options uint32) (windows.Handle, uintptr, error) {
	if !validWinGuestName(name) {
		return 0, 0, linuxErrno(fuse.EINVAL)
	}
	ntName, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return 0, 0, linuxErrno(fuse.EINVAL)
	}
	oa := windows.OBJECT_ATTRIBUTES{
		Length:        uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})),
		RootDirectory: parent,
		ObjectName:    ntName,
		Attributes:    0, // no OBJ_CASE_INSENSITIVE
	}
	var iosb windows.IO_STATUS_BLOCK
	var h windows.Handle
	err = windows.NtCreateFile(&h, access, &oa, &iosb, nil,
		windows.FILE_ATTRIBUTE_NORMAL, winShareMode, disposition, options, 0, 0)
	if err != nil {
		return 0, 0, ntStatusErrno(err)
	}
	return h, iosb.Information, nil
}

func winPathForHandle(h windows.Handle) (string, error) {
	buf := make([]uint16, 32768)
	n, err := windows.GetFinalPathNameByHandle(h, &buf[0], uint32(len(buf)), 0)
	if err != nil {
		return "", err
	}
	if n >= uint32(len(buf)) {
		return "", linuxErrno(fuse.ENAMETOOLONG)
	}
	p := windows.UTF16ToString(buf[:n])
	p = strings.TrimPrefix(p, `\\?\`)
	p = strings.TrimPrefix(p, `\??\`)
	return p, nil
}

func winExtendedPath(p string) string {
	if strings.HasPrefix(p, `\\?\`) {
		return p
	}
	if filepath.IsAbs(p) && !strings.HasPrefix(p, `\\`) {
		return `\\?\` + p
	}
	return p
}

func actualWinBase(h windows.Handle) (string, error) {
	p, err := winPathForHandle(h)
	if err != nil {
		return "", err
	}
	return filepath.Base(p), nil
}

func (b *winExportFS) rootInfo() (winFileInfo, syscall.Errno) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.closed || b.root == 0 {
		return winFileInfo{}, linuxErrno(fuse.ESTALE)
	}
	info, err := winInfoFromHandle(b.root, b.salt)
	return info, ntStatusErrno(err)
}

// resolve opens rel below the pinned root without following reparse points.
// Intermediate handles are opened relative to their parent, so a host rename
// cannot retarget the lookup outside the export.
func (b *winExportFS) resolve(rel string, access, disposition, options uint32, allowReparse bool) (windows.Handle, winFileInfo, syscall.Errno) {
	var empty winFileInfo
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.closed || b.root == 0 {
		return 0, empty, linuxErrno(fuse.ESTALE)
	}
	if rel == "" || rel == "." {
		h, err := duplicateWinHandle(b.root)
		if err != nil {
			return 0, empty, ntStatusErrno(err)
		}
		info, errno := b.infoForHandle(h)
		if errno != 0 {
			_ = windows.CloseHandle(h)
			return 0, empty, errno
		}
		return h, info, 0
	}
	rel = path.Clean(strings.ReplaceAll(rel, `\`, "/"))
	if rel == "." || strings.HasPrefix(rel, "../") || rel == ".." || strings.HasPrefix(rel, "/") {
		return 0, empty, linuxErrno(fuse.EINVAL)
	}
	parts := strings.Split(rel, "/")
	current := b.root
	defer func() {
		if current != b.root && current != 0 {
			_ = windows.CloseHandle(current)
		}
	}()
	for i, name := range parts {
		last := i == len(parts)-1
		openAccess := access
		openDisposition := disposition
		openOptions := options
		if !last {
			openAccess = winMetadataAccess
			openDisposition = windows.FILE_OPEN
			openOptions = winBaseOpenOpts | windows.FILE_DIRECTORY_FILE
		}
		h, err := b.ntOpen(current, name, openAccess, openDisposition, openOptions)
		if err != nil {
			return 0, empty, ntStatusErrno(err)
		}
		actual, err := actualWinBase(h)
		if err != nil {
			_ = windows.CloseHandle(h)
			return 0, empty, ntStatusErrno(err)
		}
		if actual != name {
			_ = windows.CloseHandle(h)
			return 0, empty, linuxErrno(fuse.ENOENT)
		}
		info, errno := b.infoForHandle(h)
		if errno != 0 {
			_ = windows.CloseHandle(h)
			return 0, empty, errno
		}
		if info.reparse && (!last || !allowReparse) {
			_ = windows.CloseHandle(h)
			return 0, empty, linuxErrno(fuse.EACCES)
		}
		if !last {
			if !info.dir || info.reparse {
				_ = windows.CloseHandle(h)
				return 0, empty, linuxErrno(fuse.ENOTDIR)
			}
			previous := current
			current = h
			if previous != b.root {
				_ = windows.CloseHandle(previous)
			}
			continue
		}
		return h, info, 0
	}
	return 0, empty, linuxErrno(fuse.ENOENT)
}

func (b *winExportFS) resolveDir(rel string) (windows.Handle, winFileInfo, syscall.Errno) {
	h, info, errno := b.resolve(rel, winMetadataAccess, windows.FILE_OPEN,
		winBaseOpenOpts|windows.FILE_DIRECTORY_FILE, false)
	if errno != 0 {
		return 0, info, errno
	}
	if !info.dir || info.reparse {
		_ = windows.CloseHandle(h)
		return 0, info, linuxErrno(fuse.ENOTDIR)
	}
	return h, info, 0
}

func (b *winExportFS) infoForHandle(h windows.Handle) (winFileInfo, syscall.Errno) {
	info, err := winInfoFromHandle(h, b.salt)
	return info, ntStatusErrno(err)
}

func winInfoFromHandle(h windows.Handle, salt uint64) (winFileInfo, error) {
	var raw windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &raw); err != nil {
		return winFileInfo{}, err
	}
	id := winFileID{
		volume: raw.VolumeSerialNumber,
		index:  uint64(raw.FileIndexHigh)<<32 | uint64(raw.FileIndexLow),
	}
	size := uint64(raw.FileSizeHigh)<<32 | uint64(raw.FileSizeLow)
	mode := uint32(fuse.S_IFREG | 0o644)
	dir := raw.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	reparse := raw.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0
	switch {
	case reparse:
		mode = fuse.S_IFLNK | 0o777
	case dir:
		mode = fuse.S_IFDIR | 0o755
	}
	if raw.FileAttributes&windows.FILE_ATTRIBUTE_READONLY != 0 {
		mode &^= 0o222
	}
	at := raw.LastAccessTime.Nanoseconds()
	mt := raw.LastWriteTime.Nanoseconds()
	ct := raw.CreationTime.Nanoseconds()
	ino := (uint64(id.volume) << 32) ^ id.index ^ salt
	if ino == 0 || ino == fuse.FUSE_ROOT_ID {
		ino ^= 0x9e3779b97f4a7c15
	}
	nlink := raw.NumberOfLinks
	if nlink == 0 {
		nlink = 1
	}
	return winFileInfo{
		id:      id,
		attrs:   raw.FileAttributes,
		dir:     dir,
		reparse: reparse,
		attr: fuse.Attr{
			Ino:       ino,
			Size:      size,
			Blocks:    (size + 511) / 512,
			Atime:     uint64(at / 1e9),
			Atimensec: uint32(at % 1e9),
			Mtime:     uint64(mt / 1e9),
			Mtimensec: uint32(mt % 1e9),
			Ctime:     uint64(ct / 1e9),
			Ctimensec: uint32(ct % 1e9),
			Mode:      mode,
			Nlink:     nlink,
			Blksize:   4096,
		},
	}, nil
}

func winOpenAccess(flags uint32) uint32 {
	access := uint32(0)
	switch flags & linuxOAccmode {
	case 0:
		access |= windows.FILE_GENERIC_READ
	case 1:
		access |= windows.FILE_GENERIC_WRITE
	case 2:
		access |= windows.FILE_GENERIC_READ | windows.FILE_GENERIC_WRITE
	}
	if flags&openWriteFlags != 0 {
		access |= windows.FILE_GENERIC_WRITE
	}
	return access | windows.SYNCHRONIZE
}

func (b *winExportFS) lookup(parentRel, name string) (winFileInfo, syscall.Errno) {
	parent, _, errno := b.resolveDir(parentRel)
	if errno != 0 {
		return winFileInfo{}, errno
	}
	defer windows.CloseHandle(parent)
	h, err := b.ntOpen(parent, name, winMetadataAccess, windows.FILE_OPEN, winBaseOpenOpts)
	if err != nil {
		return winFileInfo{}, ntStatusErrno(err)
	}
	defer windows.CloseHandle(h)
	actual, err := actualWinBase(h)
	if err != nil {
		return winFileInfo{}, ntStatusErrno(err)
	}
	if actual != name {
		return winFileInfo{}, linuxErrno(fuse.ENOENT)
	}
	info, errno := b.infoForHandle(h)
	if errno != 0 {
		return winFileInfo{}, errno
	}
	if info.reparse {
		return winFileInfo{}, linuxErrno(fuse.EACCES)
	}
	return info, 0
}

func (b *winExportFS) open(rel string, flags uint32) (*winOpenFile, winFileInfo, syscall.Errno) {
	if flags&linuxOAccmode == 3 || flags&linuxOTmpfile != 0 {
		return nil, winFileInfo{}, linuxErrno(fuse.EINVAL)
	}
	access := winOpenAccess(flags)
	h, info, errno := b.resolve(rel, access, windows.FILE_OPEN,
		winBaseOpenOpts|windows.FILE_NON_DIRECTORY_FILE, false)
	if errno != 0 {
		return nil, info, errno
	}
	if info.dir {
		_ = windows.CloseHandle(h)
		return nil, info, linuxErrno(fuse.EISDIR)
	}
	f := os.NewFile(uintptr(h), "")
	if f == nil {
		_ = windows.CloseHandle(h)
		return nil, info, linuxErrno(fuse.EIO)
	}
	wf := &winOpenFile{file: f, appendMode: flags&linuxOAppend != 0, writable: flags&linuxOAccmode != 0}
	if flags&linuxOTrunc != 0 {
		if err := f.Truncate(0); err != nil {
			_ = f.Close()
			return nil, info, ntStatusErrno(err)
		}
		info, errno = b.infoForHandle(h)
		if errno != 0 {
			_ = f.Close()
			return nil, info, errno
		}
	}
	return wf, info, 0
}

func (b *winExportFS) create(parentRel, name string, flags, mode uint32) (*winOpenFile, winFileInfo, syscall.Errno) {
	if flags&linuxOAccmode == 3 || flags&linuxODirectory != 0 || flags&linuxOTmpfile != 0 {
		return nil, winFileInfo{}, linuxErrno(fuse.EINVAL)
	}
	parent, _, errno := b.resolveDir(parentRel)
	if errno != 0 {
		return nil, winFileInfo{}, errno
	}
	defer windows.CloseHandle(parent)
	access := winOpenAccess(flags) | windows.FILE_GENERIC_WRITE
	disposition := uint32(windows.FILE_OPEN)
	switch {
	case flags&(linuxOCreat|linuxOExcl) == linuxOCreat|linuxOExcl:
		disposition = windows.FILE_CREATE
	case flags&linuxOCreat != 0:
		disposition = windows.FILE_OPEN_IF
	}
	h, createInfo, err := b.ntOpenInfo(parent, name, access, disposition,
		winBaseOpenOpts|windows.FILE_NON_DIRECTORY_FILE)
	if err != nil {
		return nil, winFileInfo{}, ntStatusErrno(err)
	}
	f := os.NewFile(uintptr(h), "")
	if f == nil {
		_ = windows.CloseHandle(h)
		return nil, winFileInfo{}, linuxErrno(fuse.EIO)
	}
	info, errno := b.infoForHandle(h)
	if errno != 0 {
		_ = f.Close()
		return nil, winFileInfo{}, errno
	}
	if info.reparse {
		_ = f.Close()
		return nil, winFileInfo{}, linuxErrno(fuse.EACCES)
	}
	if flags&linuxOTrunc != 0 {
		if err := f.Truncate(0); err != nil {
			_ = f.Close()
			return nil, winFileInfo{}, ntStatusErrno(err)
		}
		info, errno = b.infoForHandle(h)
		if errno != 0 {
			_ = f.Close()
			return nil, winFileInfo{}, errno
		}
	}
	if createInfo == winFileCreated && mode&0o222 == 0 {
		_ = b.setReadOnly(h, true)
	}
	return &winOpenFile{file: f, appendMode: flags&linuxOAppend != 0, writable: true}, info, 0
}

func (b *winExportFS) mkdir(parentRel, name string) (winFileInfo, syscall.Errno) {
	parent, _, errno := b.resolveDir(parentRel)
	if errno != 0 {
		return winFileInfo{}, errno
	}
	defer windows.CloseHandle(parent)
	h, err := b.ntOpen(parent, name,
		windows.FILE_GENERIC_READ|windows.FILE_GENERIC_WRITE,
		windows.FILE_CREATE,
		winBaseOpenOpts|windows.FILE_DIRECTORY_FILE)
	if err != nil {
		return winFileInfo{}, ntStatusErrno(err)
	}
	defer windows.CloseHandle(h)
	return b.infoForHandle(h)
}

type winDispositionInfo struct{ deleteFile byte }

func (b *winExportFS) delete(parentRel, name string, wantDir bool) syscall.Errno {
	parent, _, errno := b.resolveDir(parentRel)
	if errno != 0 {
		return errno
	}
	defer windows.CloseHandle(parent)
	h, err := b.ntOpen(parent, name,
		windows.DELETE|windows.FILE_GENERIC_READ,
		windows.FILE_OPEN,
		winBaseOpenOpts)
	if err != nil {
		return ntStatusErrno(err)
	}
	info, errno := b.infoForHandle(h)
	if errno == 0 {
		isDir := info.dir && !info.reparse
		if isDir != wantDir {
			if wantDir {
				errno = linuxErrno(fuse.ENOTDIR)
			} else {
				errno = linuxErrno(fuse.EISDIR)
			}
		}
	}
	if errno == 0 {
		var iosb windows.IO_STATUS_BLOCK
		in := winDispositionInfo{deleteFile: 1}
		errno = ntStatusErrno(windows.NtSetInformationFile(h, &iosb,
			(*byte)(unsafe.Pointer(&in)), uint32(unsafe.Sizeof(in)),
			windows.FileDispositionInformation))
	}
	_ = windows.CloseHandle(h)
	return errno
}

type winRenameInfo struct {
	replaceFlags   uint32
	rootDirectory  windows.Handle
	fileNameLength uint32
	fileName       [1]uint16
}

func (b *winExportFS) rename(oldParentRel, oldName, newParentRel, newName string, flags uint32) syscall.Errno {
	if flags&^1 != 0 { // Linux RENAME_NOREPLACE is the only phase-1 flag.
		return linuxErrno(fuse.ENOSYS)
	}
	if !validWinGuestName(newName) {
		return linuxErrno(fuse.EINVAL)
	}
	b.renameMu.Lock()
	defer b.renameMu.Unlock()
	oldParent, _, errno := b.resolveDir(oldParentRel)
	if errno != 0 {
		return errno
	}
	defer windows.CloseHandle(oldParent)
	newParent, _, errno := b.resolveDir(newParentRel)
	if errno != 0 {
		return errno
	}
	defer windows.CloseHandle(newParent)
	source, err := b.ntOpen(oldParent, oldName,
		windows.DELETE|windows.FILE_GENERIC_READ,
		windows.FILE_OPEN,
		winBaseOpenOpts)
	if err != nil {
		return ntStatusErrno(err)
	}
	defer windows.CloseHandle(source)
	name16, err := windows.UTF16FromString(newName)
	if err != nil {
		return linuxErrno(fuse.EINVAL)
	}
	name16 = name16[:len(name16)-1] // no terminating NUL in FileNameLength
	var tmpl winRenameInfo
	bufLen := int(unsafe.Offsetof(tmpl.fileName)) + len(name16)*2
	buf := make([]byte, bufLen)
	ri := (*winRenameInfo)(unsafe.Pointer(&buf[0]))
	ri.rootDirectory = newParent
	ri.fileNameLength = uint32(len(name16) * 2)
	ri.replaceFlags = windows.FILE_RENAME_POSIX_SEMANTICS
	if flags&1 == 0 {
		ri.replaceFlags |= windows.FILE_RENAME_REPLACE_IF_EXISTS
	}
	copy(unsafe.Slice((*uint16)(unsafe.Pointer(&ri.fileName[0])), len(name16)), name16)
	var iosb windows.IO_STATUS_BLOCK
	return ntStatusErrno(windows.NtSetInformationFile(source, &iosb,
		&buf[0], uint32(len(buf)), windows.FileRenameInformation))
}

// winBasicInfo mirrors FILE_BASIC_INFO for NtQuery/NtSetInformationFile.
type winBasicInfo struct {
	creationTime   int64
	lastAccessTime int64
	lastWriteTime  int64
	changeTime     int64
	attrs          uint32
	_              uint32 // alignment padding
}

// setReadOnly flips FILE_ATTRIBUTE_READONLY through the handle itself.
// The previous path-based SetFileAttributes could be retargeted at a
// replacement if the host renamed the file between operations.
func (b *winExportFS) setReadOnly(h windows.Handle, ro bool) syscall.Errno {
	var bi winBasicInfo
	var iosb windows.IO_STATUS_BLOCK
	if err := windows.NtQueryInformationFile(h, &iosb,
		(*byte)(unsafe.Pointer(&bi)), uint32(unsafe.Sizeof(bi)), windows.FileBasicInformation); err != nil {
		return ntStatusErrno(err)
	}
	attrs := bi.attrs & (windows.FILE_ATTRIBUTE_READONLY |
		windows.FILE_ATTRIBUTE_HIDDEN | windows.FILE_ATTRIBUTE_SYSTEM |
		windows.FILE_ATTRIBUTE_ARCHIVE | windows.FILE_ATTRIBUTE_TEMPORARY)
	if attrs == 0 {
		attrs = windows.FILE_ATTRIBUTE_NORMAL
	}
	if ro {
		attrs |= windows.FILE_ATTRIBUTE_READONLY
	} else {
		attrs &^= windows.FILE_ATTRIBUTE_READONLY
	}
	bi.attrs = attrs
	// the queried times are written back unchanged
	return ntStatusErrno(windows.NtSetInformationFile(h, &iosb,
		(*byte)(unsafe.Pointer(&bi)), uint32(unsafe.Sizeof(bi)), windows.FileBasicInformation))
}

func (b *winExportFS) setattr(rel string, file *winOpenFile, in *fuse.SetAttrIn) (fuse.Attr, syscall.Errno) {
	var h windows.Handle
	var closeHandle bool
	if file != nil {
		h = windows.Handle(file.file.Fd())
	} else {
		var errno syscall.Errno
		h, _, errno = b.resolve(rel,
			windows.FILE_GENERIC_READ|windows.FILE_GENERIC_WRITE,
			windows.FILE_OPEN, winBaseOpenOpts, false)
		if errno != 0 {
			return fuse.Attr{}, errno
		}
		closeHandle = true
	}
	if closeHandle {
		defer windows.CloseHandle(h)
	}
	if size, ok := in.GetSize(); ok {
		lo := int32(uint32(size))
		hi := int32(uint32(size >> 32))
		if _, err := windows.SetFilePointer(h, lo, &hi, 0); err != nil {
			return fuse.Attr{}, ntStatusErrno(err)
		}
		if err := windows.SetEndOfFile(h); err != nil {
			return fuse.Attr{}, ntStatusErrno(err)
		}
	}
	atime, hasAtime := in.GetATime()
	mtime, hasMtime := in.GetMTime()
	if hasAtime || hasMtime {
		var at, mt *windows.Filetime
		if hasAtime {
			aft := windows.NsecToFiletime(atime.UnixNano())
			at = &aft
		}
		if hasMtime {
			mft := windows.NsecToFiletime(mtime.UnixNano())
			mt = &mft
		}
		if err := windows.SetFileTime(h, nil, at, mt); err != nil {
			return fuse.Attr{}, ntStatusErrno(err)
		}
	}
	if mode, ok := in.GetMode(); ok {
		if errno := b.setReadOnly(h, mode&0o222 == 0); errno != 0 {
			return fuse.Attr{}, errno
		}
	}
	// UID/GID are intentionally squashed: Windows ACLs/SIDs cannot be
	// represented as Linux numeric owners in phase 1.
	info, errno := b.infoForHandle(h)
	return info.attr, errno
}

// procNtQueryDirectoryFile enumerates a directory through its handle;
// x/sys/windows wraps neither it nor a handle-based directory query.
var procNtQueryDirectoryFile = windows.NewLazySystemDLL("ntdll.dll").NewProc("NtQueryDirectoryFile")

const (
	// FILE_INFORMATION_CLASS value (distinct from the similarly named
	// FILE_INFO_BY_HANDLE_CLASS enum in x/sys/windows).
	ntFileIdBothDirectoryInformation = 37
	ntStatusNoMoreFiles              = 0x80000006
	ntStatusBufferOverflow           = 0x80000005

	// FILE_ID_BOTH_DIR_INFORMATION field offsets.
	winDirEntryAttrs   = 56
	winDirEntryNameLen = 60
	winDirEntryName    = 104
)

// readdir enumerates rel through the opened directory handle, so a
// concurrent host rename/replacement of the directory cannot retarget
// the listing at a reconstructed path. Per-entry metadata still comes
// from handle-relative child opens (ntOpen against the directory handle).
func (b *winExportFS) readdir(rel string) ([]fuse.DirEntry, syscall.Errno) {
	dir, info, errno := b.resolveDir(rel)
	if errno != 0 {
		return nil, errno
	}
	defer windows.CloseHandle(dir)
	entries := []fuse.DirEntry{
		{Name: ".", Mode: fuse.S_IFDIR, Ino: info.attr.Ino},
		{Name: "..", Mode: fuse.S_IFDIR},
	}
	buf := make([]byte, 256*1024)
	restart := uintptr(1)
	for {
		var iosb windows.IO_STATUS_BLOCK
		status, _, _ := syscall.SyscallN(procNtQueryDirectoryFile.Addr(),
			uintptr(dir), 0, 0, 0,
			uintptr(unsafe.Pointer(&iosb)),
			uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)),
			ntFileIdBothDirectoryInformation, 0, 0, restart)
		restart = 0
		if status == ntStatusNoMoreFiles {
			break
		}
		if status != 0 && status != ntStatusBufferOverflow {
			return nil, ntStatusErrno(syscall.Errno(status))
		}
		if iosb.Information == 0 {
			break
		}
		off := 0
		for {
			if off+winDirEntryName > int(iosb.Information) {
				break
			}
			next := *(*uint32)(unsafe.Pointer(&buf[off]))
			attrs := *(*uint32)(unsafe.Pointer(&buf[off+winDirEntryAttrs]))
			nameLen := *(*uint32)(unsafe.Pointer(&buf[off+winDirEntryNameLen]))
			if off+winDirEntryName+int(nameLen) > len(buf) {
				break
			}
			name := windows.UTF16ToString(unsafe.Slice(
				(*uint16)(unsafe.Pointer(&buf[off+winDirEntryName])), nameLen/2))
			if name != "." && name != ".." && validWinGuestName(name) {
				mode := uint32(fuse.S_IFREG)
				var ino uint64
				if child, err := b.ntOpen(dir, name, winMetadataAccess,
					windows.FILE_OPEN, winBaseOpenOpts); err == nil {
					if childInfo, errno := b.infoForHandle(child); errno == 0 {
						mode = childInfo.attr.Mode & 0o170000
						ino = childInfo.attr.Ino
					}
					_ = windows.CloseHandle(child)
				}
				if attrs&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
					mode = fuse.S_IFDIR
				}
				if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
					mode = fuse.S_IFLNK
				}
				entries = append(entries, fuse.DirEntry{Name: name, Mode: mode, Ino: ino})
			}
			if next == 0 {
				break
			}
			off += int(next)
		}
	}
	return entries, 0
}

func (b *winExportFS) statfs(out *fuse.StatfsOut) syscall.Errno {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.closed || b.root == 0 {
		return linuxErrno(fuse.ESTALE)
	}
	rootPath, err := winPathForHandle(b.root)
	if err != nil {
		return ntStatusErrno(err)
	}
	var avail, total, free uint64
	if err := windows.GetDiskFreeSpaceEx(windows.StringToUTF16Ptr(winExtendedPath(rootPath)), &avail, &total, &free); err != nil {
		return ntStatusErrno(err)
	}
	out.Blocks = total / 4096
	out.Bfree = free / 4096
	out.Bavail = avail / 4096
	out.Bsize = 4096
	out.Frsize = 4096
	out.NameLen = 255
	return 0
}

// winOpenFile owns one Windows file handle through os.File.
type winOpenFile struct {
	file       *os.File
	appendMode bool
	writable   bool // opened with any write access; Flush/Fsync gate on it
	writeMu    sync.Mutex
}

func (f *winOpenFile) close() error {
	if f == nil || f.file == nil {
		return nil
	}
	err := f.file.Close()
	f.file = nil
	return err
}

func (f *winOpenFile) read(dest []byte, off int64) (int, error) {
	n, err := f.file.ReadAt(dest, off)
	if err != nil && n > 0 {
		return n, nil
	}
	return n, err
}

func (f *winOpenFile) write(data []byte, off int64) (int, error) {
	f.writeMu.Lock()
	defer f.writeMu.Unlock()
	if f.appendMode {
		var info windows.ByHandleFileInformation
		if err := windows.GetFileInformationByHandle(windows.Handle(f.file.Fd()), &info); err != nil {
			return 0, err
		}
		off = int64(uint64(info.FileSizeHigh)<<32 | uint64(info.FileSizeLow))
	}
	return f.file.WriteAt(data, off)
}
