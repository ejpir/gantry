//go:build (linux && amd64) || windows

package vmm

import "testing"

// Reprogramming channel 0 cancels the previous timer; the cancel must be
// idempotent — the WHPX boot panicked with "close of closed channel" when
// the mode write cancelled without clearing p.cancel and armTimerLocked
// closed the same channel again (field finding from the first real
// hardware run).
func TestPITReprogramChannel0NoPanic(t *testing.T) {
	p := newPIT(func(bool) {})
	// mode write: channel 0, lohi, mode 2
	p.ioWrite(0x43, 0x34)
	p.ioWrite(0x40, 0xff)
	p.ioWrite(0x40, 0xff)
	// reprogram before the first timer fires
	p.ioWrite(0x43, 0x34)
	p.ioWrite(0x40, 0x0f)
	p.ioWrite(0x40, 0x0f)
	if p.cancel == nil {
		t.Fatal("channel 0 timer not armed after reprogramming")
	}
	p.cancel()
	p.cancel = nil
}

// Port 0x61 bit 5 (OUT2) must reflect channel 2 one-shot expiry: early TSC
// calibration polls it and spins forever when it never sets (WHPX field
// finding).
func TestPITPort61OUT2Expires(t *testing.T) {
	p := newPIT(func(bool) {})
	// channel 2, lohi, mode 0 (one-shot), tiny count so it expires fast
	p.ioWrite(0x43, 0xb0)
	p.ioWrite(0x42, 0x01)
	p.ioWrite(0x42, 0x00)
	p.ioWrite(0x61, 0x01) // GATE2 on
	if v := p.ioRead(0x61); v&0x20 != 0 {
		t.Fatalf("OUT2 set immediately after load: %#x", v)
	}
	for i := 0; i < 100000; i++ {
		if v := p.ioRead(0x61); v&0x20 != 0 {
			return
		}
	}
	t.Fatal("OUT2 never set; calibration would spin")
}
