//go:build (linux && amd64) || windows

package vmm

// Minimal cascaded i8259 PIC. KVM has an in-kernel PIC, so Linux only needs
// the port-visible shadow. WHPX uses the delivery callback when the guest boots
// with noapic: avoiding the userspace IO-APIC removes hundreds of early MMIO
// exits while retaining conventional ISA interrupt vectors.

import (
	"fmt"
	"sync"
)

type picChip struct {
	imr        byte
	irr        byte
	isr        byte
	vectorBase byte
	initStep   byte // 0=OCW/normal, 2=ICW2, 3=ICW3, 4=ICW4
	needICW4   bool
	autoEOI    bool
	readISR    bool
}

// mu guards programming and delivery state: port I/O and device IRQs arrive on
// different goroutines.
type pic8259 struct {
	mu          sync.Mutex
	master      picChip
	slave       picChip
	lines       [16]bool
	deliver     func(vector uint32)
	debugEvents uint64
}

func newPIC(deliver func(vector uint32)) *pic8259 {
	return &pic8259{
		master:  picChip{vectorBase: 0x08},
		slave:   picChip{vectorBase: 0x70},
		deliver: deliver,
	}
}

func (p *pic8259) ioRead(port uint16) byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	switch port {
	case 0x21:
		return p.master.imr
	case 0xa1:
		return p.slave.imr
	case 0x20:
		if p.master.readISR {
			return p.master.isr
		}
		return p.master.irr | p.cascadeRequestLocked()
	case 0xa0:
		if p.slave.readISR {
			return p.slave.isr
		}
		return p.slave.irr
	}
	return 0xff
}

func (p *pic8259) ioWrite(port uint16, val byte) {
	p.mu.Lock()
	if dbgIO {
		fmt.Printf("[pic] out port=%#x val=%#x\n", port, val)
	}
	chip := &p.master
	command := port == 0x20 || port == 0xa0
	if port == 0xa0 || port == 0xa1 {
		chip = &p.slave
	}
	if command {
		if val&0x10 != 0 { // ICW1: begin initialization
			chip.initStep = 2
			chip.needICW4 = val&1 != 0
			chip.imr = 0
			chip.irr = 0
			chip.isr = 0
			chip.autoEOI = false
			chip.readISR = false
		} else if val&0x18 == 0x08 { // OCW3: select IRR/ISR command reads
			if val&0x02 != 0 {
				chip.readISR = val&0x01 != 0
			}
		} else { // OCW2: EOI / priority command
			command := (val >> 5) & 7
			switch command {
			case 1, 5: // non-specific EOI (with optional rotate)
				chip.isr &^= highestPriorityBit(chip.isr)
			case 3, 7: // specific EOI (with optional rotate)
				chip.isr &^= 1 << (val & 7)
			}
		}
	} else {
		switch chip.initStep {
		case 2: // ICW2: vector offset
			chip.vectorBase = val & 0xf8
			chip.initStep = 3
		case 3: // ICW3: cascade wiring
			if chip.needICW4 {
				chip.initStep = 4
			} else {
				chip.initStep = 0
			}
		case 4: // ICW4: 8086 mode and optional automatic EOI
			chip.autoEOI = val&0x02 != 0
			chip.initStep = 0
		default: // OCW1: interrupt mask
			chip.imr = val
		}
	}
	vector, fire := p.dispatchLocked()
	deliver := p.deliver
	p.mu.Unlock()
	if fire && deliver != nil {
		deliver(vector)
	}
}

// raise latches a low-to-high edge. A real 8259 retains masked requests in
// IRR and dispatches them when unmasked; dropping those edges is enough to
// stall virtio during Linux's driver-probe mask transitions.
func (p *pic8259) raise(irq int, level bool) {
	if irq < 0 || irq >= 16 {
		return
	}
	p.mu.Lock()
	previous := p.lines[irq]
	p.lines[irq] = level
	if level && !previous {
		if irq < 8 {
			p.master.irr |= 1 << irq
		} else {
			p.slave.irr |= 1 << (irq - 8)
		}
	}
	vector, fire := p.dispatchLocked()
	deliver := p.deliver
	// UART register programming produces many redundant deassertions before
	// the first real device interrupt. Do not let those consume the bounded
	// debug trace; retain assertions and actual dispatch decisions.
	if dbgIO && (level || fire) && p.debugEvents < 200 {
		p.debugEvents++
		fmt.Printf("[pic] irq=%d level=%v vector=%#x fire=%v master=%#x/%#x/%#x slave=%#x/%#x/%#x\n",
			irq, level, vector, fire,
			p.master.irr, p.master.imr, p.master.isr,
			p.slave.irr, p.slave.imr, p.slave.isr)
	}
	p.mu.Unlock()
	if fire && deliver != nil {
		deliver(vector)
	}
}

func (p *pic8259) cascadeRequestLocked() byte {
	if pendingIRQ(p.slave.irr&^p.slave.imr, p.slave.isr) >= 0 {
		return 1 << 2
	}
	return 0
}

// dispatchLocked acknowledges at most one pending request, just as one CPU
// interrupt-acknowledge cycle would. EOI or a later device edge drives the
// next dispatch; this prevents an interrupt storm from outrunning Linux's
// handler and preserves fixed 8259 priority.
func (p *pic8259) dispatchLocked() (uint32, bool) {
	slaveIRQ := pendingIRQ(p.slave.irr&^p.slave.imr, p.slave.isr)
	masterPending := p.master.irr &^ p.master.imr
	if slaveIRQ >= 0 && p.master.imr&(1<<2) == 0 {
		masterPending |= 1 << 2
	}
	masterIRQ := pendingIRQ(masterPending, p.master.isr)
	if masterIRQ < 0 {
		return 0, false
	}
	if masterIRQ == 2 && slaveIRQ >= 0 {
		p.slave.irr &^= 1 << slaveIRQ
		if !p.slave.autoEOI {
			p.slave.isr |= 1 << slaveIRQ
		}
		if !p.master.autoEOI {
			p.master.isr |= 1 << 2
		}
		return uint32(p.slave.vectorBase) + uint32(slaveIRQ), true
	}
	p.master.irr &^= 1 << masterIRQ
	if !p.master.autoEOI {
		p.master.isr |= 1 << masterIRQ
	}
	return uint32(p.master.vectorBase) + uint32(masterIRQ), true
}

func pendingIRQ(pending, inService byte) int {
	if inService != 0 {
		// Only a higher-priority request may preempt the highest-priority ISR.
		pending &= highestPriorityBit(inService) - 1
	}
	for irq := 0; irq < 8; irq++ {
		if pending&(1<<irq) != 0 {
			return irq
		}
	}
	return -1
}

func highestPriorityBit(bits byte) byte {
	for irq := 0; irq < 8; irq++ {
		if bits&(1<<irq) != 0 {
			return 1 << irq
		}
	}
	return 0
}
