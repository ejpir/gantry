//go:build darwin

package vmm

import (
	"os"
	"syscall"
)

// allocGuestRAM reserves the guest's memory; the backend maps it into the VM
// with hv_vm_map afterwards. Split VMMs use a shared backing descriptor so a
// vhost-style filesystem backend can map the same guest pages directly.
func allocGuestRAM(size, initialCommit uint64, backing *os.File) ([]byte, error) {
	_ = initialCommit // mmap is demand-paged; no separate commit phase is needed.
	fd := -1
	flags := syscall.MAP_PRIVATE | syscall.MAP_ANON
	if backing != nil {
		fd = int(backing.Fd())
		flags = syscall.MAP_SHARED
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
