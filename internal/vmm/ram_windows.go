//go:build windows

package vmm

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// allocGuestRAM reserves guest memory outside the Go heap. A multi-gigabyte
// make([]byte, size) forces the runtime to grow and account a correspondingly
// large heap before the worker can acknowledge its bootstrap; VirtualAlloc
// reserves the address range in one operation and lets the virtio-mem path
// commit only its small boot region initially.
//
// A future Windows vhost data path can use a CreateFileMapping section here;
// reject a Unix-style backing file rather than pretending it is shared.
func allocGuestRAM(size, initialCommit uint64, backing *os.File) ([]byte, error) {
	if backing != nil {
		return nil, fmt.Errorf("shared guest RAM is not implemented on Windows")
	}
	if size == 0 || initialCommit > size {
		return nil, fmt.Errorf("invalid Windows guest RAM reservation %d/%d", initialCommit, size)
	}
	base, err := windows.VirtualAlloc(0, uintptr(size), windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		return nil, fmt.Errorf("reserve %d bytes of Windows guest RAM: %w", size, err)
	}
	// VirtualAlloc's x/sys signature returns uintptr even though the value is a
	// live allocation base; converting that API result is the intended use.
	ram := unsafe.Slice((*byte)(unsafe.Pointer(base)), int(size)) //nolint:govet
	if err := commitGuestRAM(ram, 0, initialCommit); err != nil {
		_ = windows.VirtualFree(base, 0, windows.MEM_RELEASE)
		return nil, err
	}
	return ram, nil
}

func commitGuestRAM(ram []byte, offset, size uint64) error {
	if size == 0 {
		return nil
	}
	if len(ram) == 0 || offset > uint64(len(ram)) || size > uint64(len(ram))-offset {
		return fmt.Errorf("commit Windows guest RAM range %#x+%#x outside %#x bytes", offset, size, len(ram))
	}
	address := uintptr(unsafe.Pointer(&ram[0])) + uintptr(offset)
	committed, err := windows.VirtualAlloc(address, uintptr(size), windows.MEM_COMMIT, windows.PAGE_READWRITE)
	if err != nil {
		return fmt.Errorf("commit Windows guest RAM range %#x+%#x: %w", offset, size, err)
	}
	if committed != address {
		return fmt.Errorf("commit Windows guest RAM returned address %#x, want %#x", committed, address)
	}
	return nil
}

func freeGuestRAM(ram []byte) error {
	if len(ram) == 0 {
		return nil
	}
	if err := windows.VirtualFree(uintptr(unsafe.Pointer(&ram[0])), 0, windows.MEM_RELEASE); err != nil {
		return fmt.Errorf("release Windows guest RAM reservation: %w", err)
	}
	return nil
}
