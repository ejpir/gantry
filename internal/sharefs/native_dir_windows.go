//go:build windows

package sharefs

import (
	"context"
	"encoding/binary"
	"sync"
	"syscall"
	"unsafe"

	"github.com/hanwen/go-fuse/v2/fuse"
	"golang.org/x/sys/windows"
)

// procNtQueryDirectoryFile enumerates a directory through its handle;
// x/sys/windows wraps neither it nor a handle-based directory query.
var procNtQueryDirectoryFile = windows.NewLazySystemDLL("ntdll.dll").NewProc("NtQueryDirectoryFile")

// A 64 KiB page easily fits NTFS's largest directory record while keeping
// the 4,096-handle retention ceiling from becoming a gigabyte-sized buffer
// commitment under adversarial OPENDIR fan-out.
const winDirBufferSize = 64 << 10

var winDirBuffers sync.Pool

const (
	// FILE_INFORMATION_CLASS value (distinct from the similarly named
	// FILE_INFO_BY_HANDLE_CLASS enum in x/sys/windows).
	ntFileIdBothDirectoryInformation = 37

	// FILE_ID_BOTH_DIR_INFORMATION field offsets.
	winDirEntryAttrs   = 56
	winDirEntryNameLen = 60
	winDirEntryFileID  = 96
	winDirEntryName    = 104
)

// winShareDirStream owns one pinned directory handle and a fixed-size page.
// Entries are decoded only as the guest consumes them; large directories do
// not materialize an unbounded slice or trigger one child-open syscall per
// entry. The raw bridge serializes normal reads, while mu makes Release safe
// against a malicious concurrent READDIR.
type winShareDirStream struct {
	mu     sync.Mutex
	dir    windows.Handle
	buffer *[winDirBufferSize]byte
	export *Export
	volume uint32
	salt   uint64
	rootID uint64

	valid   int
	pageOff int
	restart uintptr
	offset  uint64
	dots    uint8
	eof     bool
	closed  bool

	ready    bool
	next     fuse.DirEntry
	nextErr  syscall.Errno
	closeOne sync.Once
}

// readdir pins rel for the lifetime of a streaming DirStream. Per-entry mode
// and file identity are present in FILE_ID_BOTH_DIR_INFORMATION, so no child
// handle needs to be opened merely to list a name.
func (b *winExportFS) readdir(rel string, export *Export) (*winShareDirStream, syscall.Errno) {
	dir, info, errno := b.resolveDir(rel)
	if errno != 0 {
		return nil, errno
	}
	buffer, _ := winDirBuffers.Get().(*[winDirBufferSize]byte)
	if buffer == nil {
		buffer = new([winDirBufferSize]byte)
	}
	return &winShareDirStream{
		dir: dir, buffer: buffer, export: export, volume: b.volume, salt: b.salt,
		rootID: info.attr.Ino, restart: 1,
	}, 0
}

func (d *winShareDirStream) HasNext() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.prepareLocked()
	return d.ready || d.nextErr != 0
}

func (d *winShareDirStream) Next() (fuse.DirEntry, syscall.Errno) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.prepareLocked()
	if d.nextErr != 0 {
		errno := d.nextErr
		d.nextErr = 0
		d.eof = true
		return fuse.DirEntry{}, errno
	}
	if !d.ready {
		return fuse.DirEntry{}, 0
	}
	entry := d.next
	d.ready = false
	d.offset++
	entry.Off = d.offset
	return entry, 0
}

func (d *winShareDirStream) prepareLocked() {
	if d.nextErr != 0 || d.eof || d.closed {
		return
	}
	if d.export == nil || !d.export.usable() {
		d.ready = false
		d.nextErr = syscall.ESTALE
		return
	}
	if d.ready {
		return
	}
	entry, errno := d.readEntryLocked()
	if errno != 0 {
		d.nextErr = errno
		return
	}
	if entry == nil {
		d.eof = true
		return
	}
	d.next = *entry
	d.ready = true
}

func (d *winShareDirStream) readEntryLocked() (*fuse.DirEntry, syscall.Errno) {
	for {
		switch d.dots {
		case 0:
			d.dots++
			return &fuse.DirEntry{Name: ".", Mode: fuse.S_IFDIR, Ino: d.rootID}, 0
		case 1:
			d.dots++
			return &fuse.DirEntry{Name: "..", Mode: fuse.S_IFDIR}, 0
		}
		if d.pageOff >= d.valid {
			if errno := d.loadPageLocked(); errno != 0 {
				return nil, errno
			}
			if d.eof {
				return nil, 0
			}
		}
		buf := d.buffer[:d.valid]
		off := d.pageOff
		if off+winDirEntryName > len(buf) {
			return nil, linuxErrno(fuse.EIO)
		}
		record := buf[off:]
		next := binary.LittleEndian.Uint32(record)
		attrs := binary.LittleEndian.Uint32(record[winDirEntryAttrs:])
		nameLen := binary.LittleEndian.Uint32(record[winDirEntryNameLen:])
		fileID := binary.LittleEndian.Uint64(record[winDirEntryFileID:])
		recordLen := len(record)
		if next != 0 {
			if next&7 != 0 || next < winDirEntryName || uint64(next) > uint64(recordLen) {
				return nil, linuxErrno(fuse.EIO)
			}
			recordLen = int(next)
		}
		if nameLen&1 != 0 || uint64(nameLen) > uint64(recordLen-winDirEntryName) {
			return nil, linuxErrno(fuse.EIO)
		}
		if next == 0 {
			d.pageOff = d.valid
		} else {
			d.pageOff += int(next)
		}
		name := windows.UTF16ToString(unsafe.Slice(
			(*uint16)(unsafe.Pointer(&buf[off+winDirEntryName])), nameLen/2))
		if name == "." || name == ".." || !validWinGuestName(name) {
			continue
		}
		mode := uint32(fuse.S_IFREG)
		if attrs&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
			mode = fuse.S_IFDIR
		}
		if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			mode = fuse.S_IFLNK
		}
		ino := winGuestIno(d.volume, fileID, d.salt)
		return &fuse.DirEntry{Name: name, Mode: mode, Ino: ino}, 0
	}
}

func (d *winShareDirStream) loadPageLocked() syscall.Errno {
	var iosb windows.IO_STATUS_BLOCK
	buf := d.buffer[:]
	status, _, _ := syscall.SyscallN(procNtQueryDirectoryFile.Addr(),
		uintptr(d.dir), 0, 0, 0,
		uintptr(unsafe.Pointer(&iosb)),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)),
		ntFileIdBothDirectoryInformation, 0, 0, d.restart)
	d.restart = 0
	ntStatus := windows.NTStatus(status)
	if ntStatus == windows.STATUS_NO_MORE_FILES {
		d.eof = true
		d.valid = 0
		return 0
	}
	if ntStatus != windows.STATUS_SUCCESS && ntStatus != windows.STATUS_BUFFER_OVERFLOW {
		return ntStatusErrno(ntStatus)
	}
	if iosb.Information == 0 || iosb.Information > uintptr(len(buf)) {
		return linuxErrno(fuse.EIO)
	}
	d.valid = int(iosb.Information)
	d.pageOff = 0
	return 0
}

// Seekdir is rarely needed for virtio-fs's sequential reads. Replaying from
// the pinned handle preserves correctness without retaining every prior name.
func (d *winShareDirStream) Seekdir(_ context.Context, off uint64) syscall.Errno {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return syscall.ESTALE
	}
	if d.export == nil || !d.export.usable() {
		return syscall.ESTALE
	}
	if off > d.offset {
		// Offsets are cookies this stream previously emitted. Reject an
		// invented forward cookie without replaying a potentially huge host
		// directory merely to discover that it does not exist.
		return syscall.EINVAL
	}
	if off == d.offset {
		return 0
	}
	d.valid, d.pageOff, d.restart, d.offset, d.dots = 0, 0, 1, 0, 0
	d.eof, d.ready, d.nextErr = false, false, 0
	for d.offset < off {
		d.prepareLocked()
		if d.nextErr != 0 {
			return d.nextErr
		}
		if !d.ready {
			return syscall.EINVAL
		}
		d.ready = false
		d.offset++
	}
	return 0
}

func (d *winShareDirStream) Close() {
	d.closeOne.Do(func() {
		d.mu.Lock()
		defer d.mu.Unlock()
		d.closed = true
		if d.dir != 0 {
			_ = windows.CloseHandle(d.dir)
			d.dir = 0
		}
		if d.buffer != nil {
			winDirBuffers.Put(d.buffer)
			d.buffer = nil
		}
	})
}

func (b *winExportFS) statfs(out *fuse.StatfsOut) syscall.Errno {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.root == 0 {
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
