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
func allocGuestRAM(size, initialCommit uint64, backing *os.File) ([]byte, error) {
	if size == 0 || initialCommit > size || uint64(uintptr(size)) != size {
		return nil, fmt.Errorf("invalid Windows guest RAM reservation %d/%d", initialCommit, size)
	}
	var (
		base   uintptr
		err    error
		shared bool
	)
	if backing != nil {
		// The supervisor creates this pagefile-backed SEC_RESERVE section and
		// gives the same kernel object to the WHPX broker. Each process maps at
		// an unrelated address and refers to guest memory only by offsets.
		const fileMapReadWrite = 0x0002 | 0x0004
		base, err = windows.MapViewOfFile(windows.Handle(backing.Fd()), fileMapReadWrite, 0, 0, uintptr(size))
		shared = true
	} else {
		base, err = windows.VirtualAlloc(0, uintptr(size), windows.MEM_RESERVE, windows.PAGE_READWRITE)
	}
	if err != nil {
		return nil, fmt.Errorf("reserve %d bytes of Windows guest RAM: %w", size, err)
	}
	// VirtualAlloc and MapViewOfFile return live allocation bases; converting
	// those API results is the intended use.
	ram := unsafe.Slice((*byte)(unsafe.Pointer(base)), int(size)) //nolint:govet
	if err := commitGuestRAM(ram, 0, initialCommit); err != nil {
		if shared {
			_ = windows.UnmapViewOfFile(base)
		} else {
			_ = windows.VirtualFree(base, 0, windows.MEM_RELEASE)
		}
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

func freeGuestRAM(ram []byte, shared bool) error {
	if len(ram) == 0 {
		return nil
	}
	base := uintptr(unsafe.Pointer(&ram[0]))
	if shared {
		if err := windows.UnmapViewOfFile(base); err != nil {
			return fmt.Errorf("unmap Windows shared guest RAM: %w", err)
		}
		return nil
	}
	if err := windows.VirtualFree(base, 0, windows.MEM_RELEASE); err != nil {
		return fmt.Errorf("release Windows guest RAM reservation: %w", err)
	}
	return nil
}
