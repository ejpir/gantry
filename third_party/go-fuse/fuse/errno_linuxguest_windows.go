//go:build windows

// GANTRY PATCH: translate Windows host errors (and Go's synthetic Windows
// errno values) into the Linux errno namespace carried by virtio-fs.
package fuse

import (
	"syscall"

	"golang.org/x/sys/windows"
)

// linuxStatusErrnoBase is below Windows' application-error range and above
// real Win32 errors. It lets Gantry carry an already-translated Linux status
// through fs APIs that require syscall.Errno.
const linuxStatusErrnoBase = 1 << 28

// ErrnoFromStatus wraps a Linux FUSE status for interfaces that require a
// syscall.Errno. hostErrnoToLinux unwraps it in the bridge.
func ErrnoFromStatus(st Status) syscall.Errno {
	return syscall.Errno(linuxStatusErrnoBase + uintptr(st))
}

func hostErrnoToLinux(e syscall.Errno) Status {
	if e >= linuxStatusErrnoBase && e < linuxStatusErrnoBase+4096 {
		return Status(uintptr(e) - linuxStatusErrnoBase)
	}
	switch e {
	case 0:
		// Success: the fs bridge returns bare syscall.Errno(0) from
		// successful node ops and for negative-cache lookups. Without
		// this case every successful mutation reported EIO to the guest
		// (Linux maps identically; Darwin special-cases 0 the same way).
		return OK
	case windows.ERROR_FILE_NOT_FOUND, windows.ERROR_PATH_NOT_FOUND:
		return ENOENT
	case windows.ERROR_TOO_MANY_OPEN_FILES:
		return EMFILE
	case windows.ERROR_ACCESS_DENIED:
		return EACCES
	case windows.ERROR_INVALID_HANDLE:
		return EBADF
	case windows.ERROR_NOT_SAME_DEVICE:
		return EXDEV
	case windows.ERROR_WRITE_PROTECT:
		return EROFS
	case windows.ERROR_SHARING_VIOLATION, windows.ERROR_LOCK_VIOLATION:
		return EBUSY
	case windows.ERROR_NOT_SUPPORTED:
		return ENOTSUP
	case windows.ERROR_FILE_EXISTS, windows.ERROR_ALREADY_EXISTS:
		return EEXIST
	case windows.ERROR_BROKEN_PIPE:
		return EPIPE
	case windows.ERROR_DISK_FULL:
		return ENOSPC
	case windows.ERROR_CALL_NOT_IMPLEMENTED:
		return ENOSYS
	case windows.ERROR_INVALID_NAME:
		return EINVAL
	case windows.ERROR_DIR_NOT_EMPTY:
		return ENOTEMPTY
	case windows.ERROR_FILENAME_EXCED_RANGE:
		return ENAMETOOLONG
	case windows.ERROR_DIRECTORY:
		return ENOTDIR
	case windows.ERROR_PRIVILEGE_NOT_HELD:
		return EPERM
	}

	// Go's syscall package invents values >= APPLICATION_ERROR for common
	// Unix errors. Translate the ones the passthrough backend and bridge can
	// return directly.
	switch e {
	case syscall.EPERM:
		return EPERM
	case syscall.EINTR:
		return EINTR
	case syscall.EIO:
		return EIO
	case syscall.EBADF:
		return EBADF
	case syscall.EAGAIN:
		return EAGAIN
	case syscall.EACCES:
		return EACCES
	case syscall.EBUSY:
		return EBUSY
	case syscall.EEXIST:
		return EEXIST
	case syscall.EXDEV:
		return EXDEV
	case syscall.ENODEV:
		return ENODEV
	case syscall.ENOTDIR:
		return ENOTDIR
	case syscall.EISDIR:
		return EISDIR
	case syscall.EINVAL:
		return EINVAL
	case syscall.EROFS:
		return EROFS
	case syscall.ERANGE:
		return ERANGE
	case syscall.ENOSYS:
		return ENOSYS
	case syscall.ENOTSUP:
		return ENOTSUP
	case syscall.ENAMETOOLONG:
		return ENAMETOOLONG
	case syscall.ENOSPC:
		return ENOSPC
	case syscall.ENOTEMPTY:
		return ENOTEMPTY
	case syscall.EMFILE:
		return EMFILE
	case syscall.EPIPE:
		return EPIPE
	case syscall.ESTALE:
		return ESTALE
	}
	return EIO
}
