//go:build (linux && amd64) || windows

package vmm

import "testing"

func TestPICProgrammingAndDelivery(t *testing.T) {
	var vectors []uint32
	p := newPIC(func(vector uint32) { vectors = append(vectors, vector) })

	// Linux's conventional remap: master 0x20, slave 0x28, ICW3, ICW4.
	for _, step := range []struct {
		port uint16
		val  byte
	}{
		{0x20, 0x11}, {0x21, 0x20}, {0x21, 0x04}, {0x21, 0x01},
		{0xa0, 0x11}, {0xa1, 0x28}, {0xa1, 0x02}, {0xa1, 0x01},
	} {
		p.ioWrite(step.port, step.val)
	}
	if p.master.vectorBase != 0x20 || p.slave.vectorBase != 0x28 {
		t.Fatalf("PIC vector bases = %#x/%#x, want 0x20/0x28", p.master.vectorBase, p.slave.vectorBase)
	}
	p.raise(0, true)
	p.raise(0, false)
	// IRQ0 remains in service until Linux acknowledges it. A lower-priority
	// slave request is latched, not delivered early.
	p.raise(10, true)
	if len(vectors) != 1 || vectors[0] != 0x20 {
		t.Fatalf("delivered vectors before EOI = %#x, want [0x20]", vectors)
	}
	p.ioWrite(0x20, 0x60) // specific EOI for IRQ0
	if len(vectors) != 2 || vectors[1] != 0x2a {
		t.Fatalf("delivered vectors = %#x, want [0x20 0x2a]", vectors)
	}
	p.raise(10, false)
	p.ioWrite(0xa0, 0x62) // specific EOI for slave line 2
	p.ioWrite(0x20, 0x62) // specific EOI for cascade IRQ2

	p.ioWrite(0x21, 1) // mask IRQ0
	p.raise(0, true)
	p.raise(0, false)
	if p.master.irr&1 == 0 {
		t.Fatal("masked IRQ0 was not retained in IRR")
	}
	p.ioWrite(0x21, 0) // unmask dispatches the retained edge
	if len(vectors) != 3 || vectors[2] != 0x20 {
		t.Fatalf("unmasked retained IRQ did not dispatch: %#x", vectors)
	}
	p.ioWrite(0x20, 0x60)

	p.ioWrite(0x21, 1<<2) // mask slave cascade
	p.raise(10, true)
	if len(vectors) != 3 {
		t.Fatalf("masked IRQ delivered: %#x", vectors)
	}
	p.ioWrite(0x21, 0) // unmask cascade dispatches the retained slave edge
	if len(vectors) != 4 || vectors[3] != 0x2a {
		t.Fatalf("unmasked retained slave IRQ did not dispatch: %#x", vectors)
	}
}

func TestPICCommandReadsIRRAndISR(t *testing.T) {
	p := newPIC(func(uint32) {})
	p.ioWrite(0x21, 1<<5)
	p.raise(5, true)
	p.raise(5, false)
	p.ioWrite(0x20, 0x0a) // OCW3: read IRR
	if got := p.ioRead(0x20); got != 1<<5 {
		t.Fatalf("IRR = %#x, want %#x", got, byte(1<<5))
	}
	p.ioWrite(0x21, 0)
	p.ioWrite(0x20, 0x0b) // OCW3: read ISR
	if got := p.ioRead(0x20); got != 1<<5 {
		t.Fatalf("ISR = %#x, want %#x", got, byte(1<<5))
	}
}
