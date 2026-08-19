//go:build linux && amd64

package vmm

import "github.com/ejpir/gantry/internal/vmm/devices"

// x86Devices on KVM/linux-amd64: the legacy devices minus the I/O APIC,
// which KVM provides in-kernel (see x86devices.go for the cluster).
type x86Devices struct {
	uartIO *devices.UART16550 // x86 console (port I/O 0x3f8)
	cmos   *devices.CMOSRTC
	pit    *devices.PIT8254
	pic    *devices.PIC8259
}

// mmioX86 claims nothing: KVM services the I/O APIC window in-kernel.
func (x x86Devices) mmioX86(isWrite bool, phys uint64, data []byte) (uint32, bool) {
	return 0, false
}
