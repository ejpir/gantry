//go:build windows

package main

// allocGuestRAM: a plain Go heap slice is committed memory; WHvMapGpaRange
// pins it into the partition's physical address space.
func allocGuestRAM(size uint64) ([]byte, error) {
	return make([]byte, size), nil
}
