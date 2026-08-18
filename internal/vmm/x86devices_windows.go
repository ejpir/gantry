//go:build windows

package vmm

import (
	"github.com/ejpir/gantry/internal/gutil"
	"github.com/ejpir/gantry/internal/vmm/devices"
)

// x86Devices on WHPX: the legacy devices plus a userspace I/O APIC (WHPX
// has no in-kernel irqchip; see x86devices.go for the cluster).
type x86Devices struct {
	uartIO *devices.UART16550 // x86 console (port I/O 0x3f8)
	cmos   *devices.CMOSRTC
	ioapic *devices.IOAPIC
	pit    *devices.PIT8254
	pic    *devices.PIC8259
}

// mmioX86 services the I/O APIC MMIO window and reports whether the
// access was claimed, so the generic MMIO dispatcher can fall through to
// reads-as-zero/writes-ignored for unassigned space.
func (x x86Devices) mmioX86(isWrite bool, phys uint64, data []byte) (uint32, bool) {
	if x.ioapic == nil || phys < devices.IOAPICMMIOBase || phys >= devices.IOAPICMMIOBase+devices.IOAPICMMIOSize {
		return 0, false
	}
	var v uint32
	if isWrite {
		v = gutil.LE32(data)
	}
	return x.ioapic.MMIO(isWrite, phys-devices.IOAPICMMIOBase, v), true
}
