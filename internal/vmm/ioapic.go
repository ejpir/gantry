package vmm

// Userspace I/O APIC (82093AA) for hypervisors without an in-kernel irqchip
// (WHPX). MMIO at 0xfec00000: IOREGSEL @ 0x00, IOWIN @ 0x10. 24 pins;
// RTE[i] = reg 0x10+2i (low) / 0x11+2i (high, dest APIC id in bits 56-63).
//
// The MPS table routes ISA IRQ i to pin i; the guest programs each RTE
// (vector, edge/level, mask) and we deliver through the deliver callback
// (WHvRequestInterrupt on Windows).

import "sync"

const (
	ioApicMMIOBase = 0xfec00000
	ioApicMMIOSize = 0x20
	ioApicID       = 0x20 // matches the MPS table entry
	ioApicPins     = 24
)

type ioApic struct {
	mu      sync.Mutex
	regSel  uint32
	rte     [ioApicPins]uint64
	lines   [ioApicPins]bool
	deliver func(dest uint32, vector uint32, level bool)
}

func newIOApic(deliver func(dest, vector uint32, level bool)) *ioApic {
	a := &ioApic{deliver: deliver}
	for i := range a.rte {
		a.rte[i] = 1 << 16 // masked
	}
	return a
}

func (a *ioApic) readReg(reg uint32) uint32 {
	switch {
	case reg == 0x00:
		return ioApicID << 24
	case reg == 0x01:
		return 0x11 | (ioApicPins-1)<<16 // version 0x11, max entry 23
	case reg == 0x02:
		return 0 // arbitration id
	case reg >= 0x10 && reg < 0x10+2*ioApicPins:
		i := (reg - 0x10) / 2
		if reg&1 == 0 {
			return uint32(a.rte[i])
		}
		return uint32(a.rte[i] >> 32)
	}
	return 0
}

func (a *ioApic) writeReg(reg, val uint32) {
	switch {
	case reg == 0x00:
		return // ID: ignore writes
	case reg >= 0x10 && reg < 0x10+2*ioApicPins:
		i := (reg - 0x10) / 2
		if reg&1 == 0 {
			a.rte[i] = a.rte[i]&0xffffffff00000000 | uint64(val)
		} else {
			a.rte[i] = a.rte[i]&0x00000000ffffffff | uint64(val)<<32
		}
	}
}

// mmio handles one 32-bit access at [0, ioApicMMIOSize).
func (a *ioApic) mmio(isWrite bool, off uint64, val uint32) uint32 {
	a.mu.Lock()
	defer a.mu.Unlock()
	switch off {
	case 0x00: // IOREGSEL
		if isWrite {
			a.regSel = val
			return 0
		}
		return a.regSel
	case 0x10: // IOWIN
		if isWrite {
			a.writeReg(a.regSel, val)
			return 0
		}
		return a.readReg(a.regSel)
	}
	return 0
}

// raise drives one input line (gsi). Edge RTEs deliver on every raise(true)
// (our devices call raise once per event and lower on ack); level RTEs
// deliver on the low→high transition.
func (a *ioApic) raise(gsi int, level bool) {
	a.mu.Lock()
	rte := a.rte[gsi]
	prev := a.lines[gsi]
	a.lines[gsi] = level
	masked := rte&(1<<16) != 0
	isLevel := rte&(1<<15) != 0
	vector := uint32(rte & 0xff)
	delmode := uint32((rte >> 8) & 7)
	destModeLogical := rte&(1<<11) != 0
	dest := uint32(rte >> 56)
	fire := false
	if level && !masked && delmode == 0 { // fixed delivery only
		fire = (isLevel && !prev) || !isLevel
	}
	a.mu.Unlock()
	if fire {
		_ = destModeLogical // physical destinations only in this guest
		a.deliver(dest, vector, isLevel)
	}
}
