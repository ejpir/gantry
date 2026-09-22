//go:build (linux && amd64) || windows

package devices

import (
	"sync/atomic"
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
func TestPITCloseJoinsTimerAndRejectsRearm(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	p := NewPIT(func(bool) {
		if calls.Add(1) == 1 {
			close(entered)
			<-release
		}
	})
	p.IOWrite(0x43, 0x34) // channel 0, lohi, periodic mode 2
	p.IOWrite(0x40, 0x01)
	p.IOWrite(0x40, 0x00)
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("PIT timer did not invoke its interrupt callback")
	}

	closed := make(chan struct{})
	go func() {
		_ = p.Close()
		close(closed)
	}()
	select {
	case <-closed:
		t.Fatal("Close returned while an interrupt callback was running")
	default:
	}
	close(release)
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close did not join the timer worker")
	}

	before := calls.Load()
	p.IOWrite(0x43, 0x34)
	p.IOWrite(0x40, 0x01)
	p.IOWrite(0x40, 0x00)
	time.Sleep(2 * time.Millisecond)
	if got := calls.Load(); got != before {
		t.Fatalf("closed PIT invoked %d additional callbacks", got-before)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
}

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
