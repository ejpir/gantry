//go:build windows

package sharefs

import (
	"os"
	"syscall"
	"unsafe"

	"github.com/hanwen/go-fuse/v2/fuse"
	"golang.org/x/sys/windows"
)

func winOpenAccess(flags uint32) uint32 {
	// FUSE CREATE/OPEN replies always include attributes gathered from the
	// resulting handle. O_WRONLY does not otherwise grant FILE_READ_ATTRIBUTES
	// on Windows, so request it independently of the guest data-access mode.
	access := uint32(windows.FILE_READ_ATTRIBUTES)
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
	defer func() { _ = windows.CloseHandle(parent) }()
	h, err := b.ntOpen(parent, name, winMetadataAccess, windows.FILE_OPEN, winBaseOpenOpts)
	if err != nil {
		return winFileInfo{}, ntStatusErrno(err)
	}
	defer func() { _ = windows.CloseHandle(h) }()
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
		winBaseOpenOpts|windows.FILE_NON_DIRECTORY_FILE)
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
	return b.trackOpen(wf), info, 0
}

func (b *winExportFS) create(parentRel, name string, flags, mode uint32) (*winOpenFile, winFileInfo, syscall.Errno) {
	if flags&linuxOAccmode == 3 || flags&linuxODirectory != 0 || flags&linuxOTmpfile != 0 {
		return nil, winFileInfo{}, linuxErrno(fuse.EINVAL)
	}
	parent, _, errno := b.resolveDir(parentRel)
	if errno != 0 {
		return nil, winFileInfo{}, errno
	}
	defer func() { _ = windows.CloseHandle(parent) }()
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
	wf := &winOpenFile{file: f, appendMode: flags&linuxOAppend != 0, writable: true}
	return b.trackOpen(wf), info, 0
}

func (b *winExportFS) mkdir(parentRel, name string) (winFileInfo, syscall.Errno) {
	parent, _, errno := b.resolveDir(parentRel)
	if errno != 0 {
		return winFileInfo{}, errno
	}
	defer func() { _ = windows.CloseHandle(parent) }()
	h, err := b.ntOpen(parent, name,
		windows.FILE_GENERIC_READ|windows.FILE_GENERIC_WRITE,
		windows.FILE_CREATE,
		winBaseOpenOpts|windows.FILE_DIRECTORY_FILE)
	if err != nil {
		return winFileInfo{}, ntStatusErrno(err)
	}
	defer func() { _ = windows.CloseHandle(h) }()
	return b.infoForHandle(h)
}

type winDispositionInfo struct{ deleteFile byte }

func (b *winExportFS) delete(parentRel, name string, wantDir bool) syscall.Errno {
	parent, _, errno := b.resolveDir(parentRel)
	if errno != 0 {
		return errno
	}
	defer func() { _ = windows.CloseHandle(parent) }()
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
	defer func() { _ = windows.CloseHandle(oldParent) }()
	newParent, _, errno := b.resolveDir(newParentRel)
	if errno != 0 {
		return errno
	}
	defer func() { _ = windows.CloseHandle(newParent) }()
	source, err := b.ntOpen(oldParent, oldName,
		windows.DELETE|windows.FILE_GENERIC_READ,
		windows.FILE_OPEN,
		winBaseOpenOpts)
	if err != nil {
		return ntStatusErrno(err)
	}
	defer func() { _ = windows.CloseHandle(source) }()
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
			windows.FILE_OPEN, winBaseOpenOpts)
		if errno != 0 {
			return fuse.Attr{}, errno
		}
		closeHandle = true
	}
	if closeHandle {
		defer func() { _ = windows.CloseHandle(h) }()
	}
	if size, ok := in.GetSize(); ok {
		if size > uint64(^uint64(0)>>1) {
			return fuse.Attr{}, linuxErrno(fuse.EINVAL)
		}
		// Ftruncate sets FileEndOfFileInfo directly. SetFilePointer followed
		// by SetEndOfFile races positional I/O on the same synchronous handle.
		if err := windows.Ftruncate(h, int64(size)); err != nil {
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
