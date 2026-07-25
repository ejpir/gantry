package main

// i8259 PIC stub: with the IO-APIC in use the kernel masks the legacy PIC
// early; we just swallow the ICW/OCW sequence and report sane defaults.
// Ports 0x20/0x21 (master), 0xa0/0xa1 (slave).

import "sync"

// mu guards the IMRs: ioRead/ioWrite run on every vCPU thread.
type pic8259 struct {
	mu        sync.Mutex
	masterIMR byte
	slaveIMR  byte
}

func (p *pic8259) ioRead(port uint16) byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	switch port {
	case 0x21:
		return p.masterIMR
	case 0xa1:
		return p.slaveIMR
	}
	return 0xff
}

func (p *pic8259) ioWrite(port uint16, val byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	switch port {
	case 0x21:
		p.masterIMR = val
	case 0xa1:
		p.slaveIMR = val
	}
}
