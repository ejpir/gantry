//go:build linux

package vmm

import (
	"os"
	"syscall"
)

// allocGuestRAM reserves the guest's memory; the backend registers it with
// KVM afterwards. MAP_NORESERVE keeps it lazy. Split VMMs use a shared backing
// descriptor so a vhost-style filesystem backend maps the same guest pages.
func allocGuestRAM(size uint64, backing *os.File) ([]byte, error) {
	fd := -1
	flags := syscall.MAP_PRIVATE | syscall.MAP_ANONYMOUS | 0x4000 /* MAP_NORESERVE */
	if backing != nil {
		fd = int(backing.Fd())
		flags = syscall.MAP_SHARED | 0x4000 /* MAP_NORESERVE */
	}
	return syscall.Mmap(fd, 0, int(size),
		syscall.PROT_READ|syscall.PROT_WRITE, flags)
}

func freeGuestRAM(ram []byte) error {
	if len(ram) == 0 {
		return nil
	}
	return syscall.Munmap(ram)
}
