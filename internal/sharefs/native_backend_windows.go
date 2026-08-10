//go:build windows

package sharefs

import (
	"errors"
	"fmt"
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
	id      winFileID
	dir     bool
	reparse bool
}

// winExportFS is the native Windows passthrough backend. It keeps the export
// root open and resolves guest paths relative to open parent handles with
// NtCreateFile. Host path strings are used only to open the initial root and
// for directory enumeration/metadata calls that Windows exposes by path.
type winExportFS struct {
	root     windows.Handle
	identity Identity
	volume   uint32
	salt     uint64

	mu       sync.RWMutex
	renameMu sync.Mutex
}

const (
	winShareMode      = windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE
	winBaseOpenOpts   = windows.FILE_OPEN_FOR_BACKUP_INTENT | windows.FILE_OPEN_REPARSE_POINT | windows.FILE_SYNCHRONOUS_IO_NONALERT
	winMetadataAccess = windows.FILE_GENERIC_READ
	winFileCreated    = 2 // IO_STATUS_BLOCK Information for NtCreateFile
)

func newWinExportFS(rootPath string, salt uint64) (*winExportFS, error) {
	clean, err := cleanWinSharePath(rootPath)
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
	finalPath, err := winPathForHandle(root)
	if err != nil {
		_ = windows.CloseHandle(root)
		return nil, fmt.Errorf("resolve pinned share root: %w", err)
	}
	finalPath, err = cleanWinSharePath(finalPath)
	if err != nil {
		_ = windows.CloseHandle(root)
		return nil, fmt.Errorf("resolve pinned share root: %w", err)
	}
	identity := newIdentity(finalPath, uint64(info.id.volume), info.id.index, true)
	return &winExportFS{root: root, identity: identity, volume: info.id.volume, salt: salt}, nil
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
	return err
}

// cleanWinSharePath performs syntactic validation only. Security-relevant
// attributes and the canonical path are read from the handle after open.
func cleanWinSharePath(p string) (string, error) {
	if p == "" {
		return "", fmt.Errorf("share path is empty")
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	if len(abs) >= len(`\\?\UNC\`) && strings.EqualFold(abs[:len(`\\?\UNC\`)], `\\?\UNC\`) {
		return "", fmt.Errorf("UNC/network share roots are not supported: %s", p)
	}
	abs = strings.TrimPrefix(abs, `\\?\`)
	if strings.HasPrefix(abs, `\\`) {
		return "", fmt.Errorf("UNC/network share roots are not supported: %s", p)
	}
	if filepath.VolumeName(abs) == "" {
		return "", fmt.Errorf("share path must include a drive: %s", p)
	}
	return filepath.Clean(abs), nil
}

func openWinRoot(p string) (windows.Handle, error) {
	name := p
	name = strings.TrimPrefix(name, `\\?\`)
	name = strings.TrimPrefix(name, `\??\`)
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

func winGuestIno(volume uint32, fileID, salt uint64) uint64 {
	ino := (uint64(volume) << 32) ^ fileID ^ salt
	if ino == 0 || ino == fuse.FUSE_ROOT_ID {
		ino ^= 0x9e3779b97f4a7c15
	}
	return ino
}

func validWinGuestName(name string) bool {
	if name == "" || name == "." || name == ".." || !utf8.ValidString(name) || strings.ContainsAny(name, "/\\\x00:") {
		return false
	}
	if strings.HasSuffix(name, " ") || strings.HasSuffix(name, ".") {
		return false
	}
	base := name
	if i := strings.IndexByte(name, '.'); i >= 0 {
		base = base[:i]
	}
	if len(base) == 3 {
		return !strings.EqualFold(base, "CON") &&
			!strings.EqualFold(base, "PRN") &&
			!strings.EqualFold(base, "AUX") &&
			!strings.EqualFold(base, "NUL")
	}
	if len(base) == 4 && base[3] >= '1' && base[3] <= '9' {
		prefix := base[:3]
		return !strings.EqualFold(prefix, "COM") && !strings.EqualFold(prefix, "LPT")
	}
	return true
}
