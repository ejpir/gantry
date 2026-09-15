//go:build windows

package vmm

import (
	"reflect"
	"unsafe"
)

// windowsByteSlice exposes memory returned by VirtualAlloc or MapViewOfFile as
// a byte slice. Windows represents those allocation bases as uintptr, so build
// the slice header directly instead of converting a stored uintptr back to an
// unsafe.Pointer (which is both discouraged by the unsafe rules and rejected
// by go vet's unsafeptr analyzer). The memory is outside the Go heap and its
// lifetime remains owned by the corresponding Windows allocation or mapping.
func windowsByteSlice(address uintptr, length int) []byte {
	var memory []byte
	header := (*reflect.SliceHeader)(unsafe.Pointer(&memory)) //nolint:staticcheck // Windows returns external memory as uintptr.
	header.Data = address
	header.Len = length
	header.Cap = length
	return memory
}
