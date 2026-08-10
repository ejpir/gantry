//go:build windows

package vmm

// allocGuestRAM: a plain Go heap slice is committed memory; WHvMapGpaRange
// pins it into the partition's physical address space.
func allocGuestRAM(size uint64) ([]byte, error) {
	return make([]byte, size), nil
}

// Windows guest RAM is a Go heap allocation; dropping the final references
// returns it to the runtime rather than an OS mmap API.
func freeGuestRAM([]byte) error { return nil }
