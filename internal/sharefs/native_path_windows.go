//go:build windows

package sharefs

import (
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"github.com/hanwen/go-fuse/v2/fuse"
	"golang.org/x/sys/windows"
)

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
	var stack [512]uint16
	n, err := windows.GetFinalPathNameByHandle(h, &stack[0], uint32(len(stack)), 0)
	if err != nil {
		return "", err
	}
	if n < uint32(len(stack)) {
		return cleanFinalWinPath(stack[:n]), nil
	}
	buf := make([]uint16, n+1)
	n, err = windows.GetFinalPathNameByHandle(h, &buf[0], uint32(len(buf)), 0)
	if err != nil {
		return "", err
	}
	if n >= uint32(len(buf)) {
		return "", linuxErrno(fuse.ENAMETOOLONG)
	}
	return cleanFinalWinPath(buf[:n]), nil
}

func cleanFinalWinPath(buf []uint16) string {
	p := windows.UTF16ToString(buf)
	p = strings.TrimPrefix(p, `\\?\`)
	p = strings.TrimPrefix(p, `\??\`)
	return p
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

// resolve opens rel below the pinned root without following reparse points.
// Intermediate handles are opened relative to their parent, so a host rename
// cannot retarget the lookup outside the export.
func (b *winExportFS) resolve(rel string, access, disposition, options uint32) (windows.Handle, winFileInfo, syscall.Errno) {
	var empty winFileInfo
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.root == 0 {
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
		if info.reparse {
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
		winBaseOpenOpts|windows.FILE_DIRECTORY_FILE)
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
	ino := winGuestIno(id.volume, id.index, salt)
	nlink := raw.NumberOfLinks
	if nlink == 0 {
		nlink = 1
	}
	return winFileInfo{
		id:      id,
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
