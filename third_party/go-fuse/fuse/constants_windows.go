//go:build windows

// GANTRY PATCH: Linux-guest constants for the Windows native-passthrough
// backend. The virtio-fs peer is always Linux, so host os/syscall flag
// values must not leak onto the wire.
package fuse

const (
	FUSE_ROOT_ID = 1

	FUSE_UNKNOWN_INO = 0xffffffff

	CUSE_UNRESTRICTED_IOCTL = (1 << 0)

	FUSE_LK_FLOCK = (1 << 0)

	FUSE_RELEASE_FLUSH        = (1 << 0)
	FUSE_RELEASE_FLOCK_UNLOCK = (1 << 1)

	FUSE_IOCTL_MAX_IOV = 256

	FUSE_POLL_SCHEDULE_NOTIFY = (1 << 0)

	CUSE_INIT_INFO_MAX = 4096

	// Linux file type bits.
	S_IFMT  = 0o170000
	S_IFDIR = 0o040000
	S_IFREG = 0o100000
	S_IFLNK = 0o120000
	S_IFIFO = 0o010000

	CUSE_INIT = 4096

	// Linux O_WRONLY|O_RDWR|O_APPEND|O_CREAT|O_TRUNC.
	O_ANYWRITE = uint32(0x1 | 0x2 | 0x400 | 0x40 | 0x200)

	FMODE_EXEC = 0x20

	logicalBlockSize = 4096
)
