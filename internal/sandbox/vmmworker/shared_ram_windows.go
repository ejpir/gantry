//go:build windows

package vmmworker

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

const windowsSECReserve = 0x04000000

// newSharedRAM creates a pagefile-backed section with no reusable name. WHPX
// maps one view while the AppContainer device worker maps another; authority
// to the bytes is conveyed only by an explicitly inherited section handle.
func newSharedRAM(_ string, size uint64) (*os.File, error) {
	if size == 0 || uint64(uintptr(size)) != size {
		return nil, fmt.Errorf("shared guest RAM: invalid size %d", size)
	}
	handle, err := windows.CreateFileMapping(
		windows.InvalidHandle, nil, windows.PAGE_READWRITE|windowsSECReserve,
		uint32(size>>32), uint32(size), nil,
	)
	if err != nil {
		return nil, fmt.Errorf("create Windows shared guest RAM section: %w", err)
	}
	file := os.NewFile(uintptr(handle), "gantry-guest-ram")
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, fmt.Errorf("wrap Windows shared guest RAM section")
	}
	return file, nil
}
