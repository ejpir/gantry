//go:build (linux && amd64) || windows

package devices

import (
	"testing"
	"time"
)

// Reprogramming channel 0 cancels the previous timer; the cancel must be
// idempotent — the WHPX boot panicked with "close of closed channel" when
// the mode write cancelled without clearing p.cancel and armTimerLocked
// closed the same channel again (field finding from the first real
// hardware run).
func TestPITReprogramChannel0NoPanic(t *testing.T) {
	p := NewPIT(func(bool) {})
	// mode write: channel 0, lohi, mode 2
	p.IOWrite(0x43, 0x34)
	p.IOWrite(0x40, 0xff)
	p.IOWrite(0x40, 0xff)
	// reprogram before the first timer fires
	p.IOWrite(0x43, 0x34)
	p.IOWrite(0x40, 0x0f)
	p.IOWrite(0x40, 0x0f)
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
	p := NewPIT(func(bool) {})
	now := time.Unix(1, 0)
	p.now = func() time.Time { return now }
	// channel 2, lohi, mode 0 (one-shot), one PIT tick
	p.IOWrite(0x43, 0xb0)
	p.IOWrite(0x42, 0x01)
	p.IOWrite(0x42, 0x00)
	p.IOWrite(0x61, 0x01) // GATE2 on
	if v := p.IORead(0x61); v&0x20 != 0 {
		t.Fatalf("OUT2 set immediately after load: %#x", v)
	}
	now = now.Add(time.Millisecond)
	if v := p.IORead(0x61); v&0x20 == 0 {
		t.Fatalf("OUT2 did not set after expiry: %#x", v)
	}
}
