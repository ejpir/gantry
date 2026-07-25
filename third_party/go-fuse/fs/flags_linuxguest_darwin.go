//go:build darwin

package fs

import "syscall"

// openFlagsToHost translates Linux O_* values carried by FUSE into Darwin
// values accepted by os.OpenFile/openat.
func openFlagsToHost(f uint32) int {
	h := int(f & 0x3) // O_RDONLY/O_WRONLY/O_RDWR are identical.
	if f&0x40 != 0 {  // Linux O_CREAT
		h |= syscall.O_CREAT
	}
	if f&0x80 != 0 { // O_EXCL
		h |= syscall.O_EXCL
	}
	if f&0x100 != 0 { // O_NOCTTY
		h |= syscall.O_NOCTTY
	}
	if f&0x200 != 0 { // O_TRUNC
		h |= syscall.O_TRUNC
	}
	if f&0x400 != 0 { // O_APPEND
		h |= syscall.O_APPEND
	}
	if f&0x800 != 0 { // O_NONBLOCK
		h |= syscall.O_NONBLOCK
	}
	if f&0x101000 != 0 { // Linux O_DSYNC/O_SYNC
		h |= syscall.O_SYNC
	}
	if f&0x10000 != 0 { // O_DIRECTORY
		h |= syscall.O_DIRECTORY
	}
	if f&0x20000 != 0 { // O_NOFOLLOW
		h |= syscall.O_NOFOLLOW
	}
	if f&0x80000 != 0 { // O_CLOEXEC
		h |= syscall.O_CLOEXEC
	}
	// Linux O_LARGEFILE, O_DIRECT and O_PATH have no useful Darwin
	// equivalent for this loopback server and are intentionally ignored.
	return h
}

func xattrFlagsToHost(f uint32) int {
	var h int
	if f&1 != 0 { // Linux XATTR_CREATE
		h |= 0x2 // Darwin XATTR_CREATE
	}
	if f&2 != 0 { // Linux XATTR_REPLACE
		h |= 0x4 // Darwin XATTR_REPLACE
	}
	return h
}

func renameFlagsToHost(f uint32) (uint, syscall.Errno) {
	var h uint
	if f&1 != 0 { // Linux RENAME_NOREPLACE
		h |= 0x4 // Darwin RENAME_EXCL
	}
	if f&2 != 0 { // RENAME_EXCHANGE / RENAME_SWAP
		h |= 0x2
	}
	if f&^uint32(3) != 0 { // RENAME_WHITEOUT or unknown
		return 0, syscall.ENOTSUP
	}
	return h, 0
}
