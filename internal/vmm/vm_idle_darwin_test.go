//go:build darwin

package vmm

import (
	"strings"
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

func TestStalledVCPUHandlesSelectsOnlyRunningStalls(t *testing.T) {
	now := time.Now().UnixNano()
	vcpus := []*hvfVCPU{
		{id: 0, vcpu: 100},
		{id: 1, vcpu: 101},
		{id: 2, vcpu: 102},
		{id: 3, vcpu: 103},
	}
	for _, vc := range vcpus {
		vc.inHVF.Store(true)
	}
	vcpus[0].lastRunEntry.Store(now - int64(vcpuLivenessLimit))
	vcpus[1].lastRunEntry.Store(now - int64(vcpuLivenessLimit/2))
	vcpus[2].inHVF.Store(false)
	vcpus[2].lastRunEntry.Store(now - int64(2*vcpuLivenessLimit))
	// vCPU 3 has entered no run loop yet and therefore has no timestamp.

	handles := stalledVCPUHandles(vcpus, now)
	if len(handles) != 1 || handles[0] != 100 {
		t.Fatalf("stalled handles = %v, want [100]", handles)
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

func TestHVFIRQCoalescingRearmsOnDeassert(t *testing.T) {
	stats := new(hvfRuntimeStats)
	b := &hvfBackend{coalesceIRQs: true, runtimeStats: stats}
	for index, test := range []struct {
		level bool
		want  bool
	}{
		{level: true, want: true},
		{level: true, want: false},
		{level: false, want: true},
		{level: false, want: false},
		{level: true, want: true},
	} {
		if got := b.shouldDeliverIRQ(73, test.level); got != test.want {
			t.Errorf("transition %d level %t deliver = %t, want %t", index, test.level, got, test.want)
		}
	}
	if got := stats.gicSuppressed.Load(); got != 2 {
		t.Errorf("suppressed transitions = %d, want 2", got)
	}
	if got := stats.gicIRQSuppressed[73].Load(); got != 2 {
		t.Errorf("IRQ 73 suppressed transitions = %d, want 2", got)
	}

	plain := &hvfBackend{}
	if !plain.shouldDeliverIRQ(73, true) || !plain.shouldDeliverIRQ(73, true) {
		t.Fatal("coalescing disabled suppressed a repeated level")
	}
}

func TestHVFRuntimeStatsLineReportsWithoutKicking(t *testing.T) {
	now := time.Now()
	stats := new(hvfRuntimeStats)
	stats.gicAssertions.Store(3)
	stats.gicDeassertions.Store(1)
	stats.gicIRQAssertions[73].Store(3)
	stats.gicIRQDeassertions[73].Store(1)
	stats.gicSuppressed.Store(2)
	stats.gicIRQSuppressed[73].Store(2)
	stats.gicNanos.Store(int64(16 * time.Microsecond))
	stats.gicMaximum.Store(int64(7 * time.Microsecond))
	stats.livenessBatches.Store(2)
	stats.livenessTargets.Store(3)
	stats.livenessNanos.Store(int64(10 * time.Microsecond))
	stats.livenessMaximum.Store(int64(8 * time.Microsecond))
	stats.livenessStarted.Store(now.Add(-250 * time.Millisecond).UnixNano())
	stats.livenessInFlight.Store(true)
	stats.kickBatches.Store(1)
	stats.kickTargets.Store(4)

	vc0 := &hvfVCPU{id: 0}
	vc0.statLiveness.Store(2)
	vc0.statCanceled.Store(2)
	vc0.inHVF.Store(true)
	vc0.lastRunEntry.Store(now.Add(-300 * time.Millisecond).UnixNano())
	vc1 := &hvfVCPU{id: 1}
	vc1.statLiveness.Store(1)
	vc1.statCanceled.Store(1)
	b := &hvfBackend{runtimeStats: stats, vcpus: []*hvfVCPU{vc1, vc0}}

	line := b.runtimeStatsLine(now)
	for _, want := range []string{
		"gic(assert=3 deassert=1 suppressed=2 avg=4µs max=7µs per-irq=[73:3/1/2])",
		"liveness(batches=2 targets=3 avg=5µs max=8µs in-flight=yes:250ms per-cpu=[0:2,1:1])",
		"other-kicks(batches=1 targets=4)",
		"canceled=[0:2,1:1]", "in-hvf=[0:300ms]", "vcpu-lock=available",
	} {
		if !strings.Contains(line, want) {
			t.Errorf("runtime stats line %q does not contain %q", line, want)
		}
	}

	b.vcpuMu.Lock()
	busyLine := b.runtimeStatsLine(now)
	b.vcpuMu.Unlock()
	if !strings.Contains(busyLine, "vcpu-lock=busy") || !strings.Contains(busyLine, "per-cpu=[]") {
		t.Errorf("busy runtime stats line did not remain nonblocking: %q", busyLine)
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
