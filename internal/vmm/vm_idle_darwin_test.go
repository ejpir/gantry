//go:build darwin

package vmm

import (
	"testing"
	"time"
)

// A device interrupt raised while the guest is parked must release the vCPU
// at once. hv_vcpus_exit cannot do it — an idling vCPU is outside the
// hypervisor — so the wake path is the only thing standing between a virtio
// completion and a full idleBound of dead wall time.
func TestIdleWakesOnInterrupt(t *testing.T) {
	vc := &hvfVCPU{wake: make(chan struct{}, 1), bootAccounting: true}
	// The interrupt may arrive after hv_vcpu_run exits but before idle starts.
	// Queue it first to exercise that lost-wakeup boundary deterministically;
	// sub-millisecond sleeps are coalesced on loaded macOS CI runners.
	vc.signalWake()

	vc.idle()
	if vc.idleCapped.Load() != 0 {
		t.Errorf("wakeup counted as a bound expiry")
	}
	if vc.idleWaits.Load() != 1 {
		t.Errorf("idle waits = %d, want 1", vc.idleWaits.Load())
	}
	if vc.idleBlocked.Load() <= 0 {
		t.Errorf("idle blocked time not accounted")
	}
}

// Nothing to wake it: the bound paces the guest instead of spinning a core.
func TestIdleFallsBackToBound(t *testing.T) {
	vc := &hvfVCPU{wake: make(chan struct{}, 1), bootAccounting: true}
	start := time.Now()
	vc.idle()
	if blocked := time.Since(start); blocked < idleBound {
		t.Fatalf("idle blocked %v, want at least the %v bound", blocked, idleBound)
	}
	if vc.idleCapped.Load() != 1 {
		t.Errorf("bound expiry = %d, want 1", vc.idleCapped.Load())
	}
}

// signalWake is called from device goroutines and must never block, whatever
// the vCPU is doing.
func TestSignalWakeNeverBlocks(t *testing.T) {
	vc := &hvfVCPU{wake: make(chan struct{}, 1)}
	done := make(chan struct{})
	go func() {
		for range 100 {
			vc.signalWake()
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("signalWake blocked")
	}
}

func TestIRQWakeTargetsAffinityCPUAndCompatibilityCPU0(t *testing.T) {
	b := &hvfBackend{m: &Machine{vcpus: 4, irqTargets: map[int]int{73: 1}}}
	for id := range 4 {
		b.vcpus = append(b.vcpus, &hvfVCPU{id: id, wake: make(chan struct{}, 1)})
	}

	b.wakeIRQTarget(73)
	for id, vc := range b.vcpus {
		woke := false
		select {
		case <-vc.wake:
			woke = true
		default:
		}
		want := id == 0 || id == 1
		if woke != want {
			t.Errorf("vCPU %d wake = %v, want %v", id, woke, want)
		}
	}
}

func TestIRQWakeUnknownRouteUsesCPU0Only(t *testing.T) {
	b := &hvfBackend{m: &Machine{vcpus: 3}}
	for id := range 3 {
		b.vcpus = append(b.vcpus, &hvfVCPU{id: id, wake: make(chan struct{}, 1)})
	}

	b.wakeIRQTarget(99)
	for id, vc := range b.vcpus {
		select {
		case <-vc.wake:
			if id != 0 {
				t.Errorf("unknown IRQ woke vCPU %d, want CPU 0 only", id)
			}
		default:
			if id == 0 {
				t.Fatal("unknown IRQ did not wake compatibility CPU 0")
			}
		}
	}
}

func TestHVFUnknownExitRetryIsBounded(t *testing.T) {
	for attempt := 1; attempt <= hvfUnknownRetryLimit; attempt++ {
		delay, retry := hvfUnknownRetryDelay(attempt)
		if !retry || delay != time.Duration(attempt)*time.Millisecond {
			t.Fatalf("attempt %d = delay %s retry %v", attempt, delay, retry)
		}
	}
	for _, attempt := range []int{0, hvfUnknownRetryLimit + 1} {
		if delay, retry := hvfUnknownRetryDelay(attempt); retry || delay != 0 {
			t.Fatalf("out-of-range attempt %d = delay %s retry %v", attempt, delay, retry)
		}
	}
}

func TestRunStatsAggregatesVCPUs(t *testing.T) {
	b := &hvfBackend{}
	for range 2 {
		vc := &hvfVCPU{wake: make(chan struct{}, 1)}
		vc.statExits.Store(10)
		vc.statWFI.Store(3)
		vc.statMMIO.Store(5)
		vc.statSysreg.Store(1)
		vc.statOther.Store(1)
		vc.idleWaits.Store(3)
		vc.idleBlocked.Store(int64(2 * time.Millisecond))
		vc.idleCapped.Store(1)
		b.vcpus = append(b.vcpus, vc)
	}
	want := runStats{
		Exits: 20, WFI: 6, MMIO: 10, Sysreg: 2, Other: 2,
		IdleWaits: 6, IdleCapped: 2, IdleBlocked: 4 * time.Millisecond,
	}
	if got := b.runStats(); got != want {
		t.Fatalf("runStats = %+v, want %+v", got, want)
	}
}
