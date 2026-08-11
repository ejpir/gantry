//go:build linux

package vhostuser

import (
	"syscall"

	"golang.org/x/sys/unix"
)

func mapSharedRegion(fd int, offset int64, size int) ([]byte, error) {
	return syscall.Mmap(fd, offset, size, syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_SHARED|syscall.MAP_NORESERVE)
}

func unmapRegion(data []byte) error { return syscall.Munmap(data) }

func dontDump(data []byte) { _ = syscall.Madvise(data, unix.MADV_DONTDUMP) }
