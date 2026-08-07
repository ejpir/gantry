//go:build windows

package vmm

import "github.com/ejpir/gantry/internal/gutil"

// x86Devices on WHPX: the legacy devices plus a userspace I/O APIC (WHPX
// has no in-kernel irqchip; see x86devices.go for the cluster).
type x86Devices struct {
	uartIO *uart16550 // x86 console (port I/O 0x3f8)
	cmos   *cmosRTC
	ioapic *ioApic
	pit    *pit8254
	pic    *pic8259
}

// mmioX86 services the I/O APIC MMIO window and reports whether the
// access was claimed, so the generic MMIO dispatcher can fall through to
// reads-as-zero/writes-ignored for unassigned space.
func (x x86Devices) mmioX86(isWrite bool, phys uint64, data []byte) (uint32, bool) {
	if x.ioapic == nil || phys < ioApicMMIOBase || phys >= ioApicMMIOBase+ioApicMMIOSize {
		return 0, false
	}
	var v uint32
	if isWrite {
		v = gutil.LE32(data)
	}
	return x.ioapic.mmio(isWrite, phys-ioApicMMIOBase, v), true
}
