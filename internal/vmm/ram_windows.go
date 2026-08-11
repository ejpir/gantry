//go:build windows

package vmm

import (
	"fmt"
	"os"
)

// allocGuestRAM: a plain Go heap slice is committed memory; WHvMapGpaRange
// pins it into the partition's physical address space. A future Windows split
// VMM maps a CreateFileMapping section here; reject a Unix-style backing file
// rather than pretending it is shared.
func allocGuestRAM(size uint64, backing *os.File) ([]byte, error) {
	if backing != nil {
		return nil, fmt.Errorf("shared guest RAM is not implemented on Windows")
	}
	return make([]byte, size), nil
}

// Windows guest RAM is a Go heap allocation; dropping the final references
// returns it to the runtime rather than an OS mmap API.
func freeGuestRAM([]byte) error { return nil }
