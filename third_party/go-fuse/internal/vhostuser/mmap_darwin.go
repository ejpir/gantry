//go:build darwin

package vhostuser

import "syscall"

func mapSharedRegion(fd int, offset int64, size int) ([]byte, error) {
	return syscall.Mmap(fd, offset, size, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
}

func unmapRegion(data []byte) error { return syscall.Munmap(data) }

// Darwin has no MADV_DONTDUMP equivalent. The shared RAM object is unlinked
// and reachable only through inherited/transferred descriptors.
func dontDump([]byte) {}
