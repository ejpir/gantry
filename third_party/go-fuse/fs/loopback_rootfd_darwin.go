//go:build darwin

package fs

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

// loopbackRootFDPath returns the current path of a pinned directory. Unlike
// Linux /proc/self/fd, Darwin /dev/fd is not reliable as a path prefix for
// directory traversal; F_GETPATH follows renames while preserving confinement
// to the originally opened directory descriptor.
func loopbackRootFDPath(fd int, fallback string) string {
	var buf [4096]byte
	_, _, errno := unix.Syscall(unix.SYS_FCNTL, uintptr(fd), uintptr(unix.F_GETPATH), uintptr(unsafe.Pointer(&buf[0])))
	if errno != 0 {
		return fallback
	}
	return unix.ByteSliceToString(buf[:])
}
