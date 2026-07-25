//go:build linux

package main

import "syscall"

// allocGuestRAM reserves the guest's memory; the backend registers it with
// KVM afterwards. MAP_NORESERVE keeps it lazy.
func allocGuestRAM(size uint64) ([]byte, error) {
	return syscall.Mmap(-1, 0, int(size),
		syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_PRIVATE|syscall.MAP_ANONYMOUS|0x4000 /* MAP_NORESERVE */)
}
