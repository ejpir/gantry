//go:build darwin

package vmm

import "syscall"

// allocGuestRAM reserves the guest's memory; the backend maps it into the VM
// with hv_vm_map afterwards.
func allocGuestRAM(size uint64) ([]byte, error) {
	return syscall.Mmap(-1, 0, int(size),
		syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_PRIVATE|syscall.MAP_ANON)
}
