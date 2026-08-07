//go:build (linux && amd64) || windows

package vmm

import "testing"

func TestUART16550Tx(t *testing.T) {
	var out []byte
	u := newUART16550(func(bool) {}, func(b byte) { out = append(out, b) })
	u.ioWrite(x86SerialPort+0, 'h')
	u.ioWrite(x86SerialPort+0, 'i')
	if string(out) != "hi" {
		t.Errorf("out = %q", out)
	}
	// LSR always reports THR empty / transmitter idle
	if lsr := u.ioRead(x86SerialPort + 5); lsr&0x60 != 0x60 {
		t.Errorf("LSR = %#x, want THRE|TEMT set", lsr)
	}
	// and no data ready
	if lsr := u.ioRead(x86SerialPort + 5); lsr&0x01 != 0 {
		t.Errorf("LSR = %#x, unexpected DR", lsr)
	}
}

func TestUART16550RxIRQ(t *testing.T) {
	var levels []bool
	u := newUART16550(func(l bool) { levels = append(levels, l) }, func(byte) {})
	u.ioWrite(x86SerialPort+1, 0x01) // IER: RX interrupt enable
	u.feed([]byte("ab"))
	if len(levels) == 0 || !levels[len(levels)-1] {
		t.Fatal("no IRQ raised on rx")
	}
	if lsr := u.ioRead(x86SerialPort + 5); lsr&0x01 == 0 {
		t.Error("LSR.DR not set after feed")
	}
	if iir := u.ioRead(x86SerialPort + 2); iir&0x0f != 0x04 {
		t.Errorf("IIR = %#x, want RDA pending (0x04)", iir)
	}
	if b := u.ioRead(x86SerialPort); b != 'a' {
		t.Errorf("RBR = %q", b)
	}
	if b := u.ioRead(x86SerialPort); b != 'b' {
		t.Errorf("RBR = %q", b)
	}
	// drained: line lowered, LSR.DR clear
	if levels[len(levels)-1] != false {
		t.Error("IRQ not lowered after fifo drained")
	}
	if lsr := u.ioRead(x86SerialPort + 5); lsr&0x01 != 0 {
		t.Error("LSR.DR still set")
	}
}

func TestUART16550DLAB(t *testing.T) {
	u := newUART16550(func(bool) {}, func(byte) {})
	u.ioWrite(x86SerialPort+3, 0x80) // LCR: set DLAB
	u.ioWrite(x86SerialPort+0, 0x0c) // DLL
	u.ioWrite(x86SerialPort+1, 0x00) // DLM
	if got := u.ioRead(x86SerialPort + 0); got != 0x0c {
		t.Errorf("DLL readback = %#x", got)
	}
	u.ioWrite(x86SerialPort+3, 0x03) // 8N1, DLAB clear
	// now reg 0 is THR/RBR again, not DLL
	if got := u.ioRead(x86SerialPort + 0); got != 0x00 {
		t.Errorf("RBR with DLAB clear = %#x", got)
	}
	if got := u.ioRead(x86SerialPort + 3); got != 0x03 {
		t.Errorf("LCR = %#x", got)
	}
}

func TestCMOSRTCClock(t *testing.T) {
	c := &cmosRTC{}
	read := func(reg byte) byte {
		c.ioWrite(cmosIndexPort, reg)
		return c.ioRead(cmosDataPort)
	}
	if d := read(0x0d); d&0x80 == 0 {
		t.Error("reg D VRT bit not set")
	}
	if b := read(0x0b); b != 0x02 {
		t.Errorf("reg B = %#x (want 24h/BCD)", b)
	}
	// BCD sanity: hour register is a valid BCD value <= 23
	h := read(0x04)
	if h&0x0f > 9 || h>>4 > 2 {
		t.Errorf("hour reg %#x not BCD", h)
	}
}
