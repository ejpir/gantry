package vmm

import (
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// bootMilestone identifies one first-occurrence guest event. The timeline is
// diagnostic-only (GANTRY_BOOT_TIMING=1), so the normal boot path carries no
// timestamp or formatting work. Enabled boots pay one atomic load at each
// relevant MMIO access and emit at most one line per milestone.
type bootMilestone uint32

const (
	bootFirstUART bootMilestone = 1 << iota
	bootFirstVirtioMMIO
	bootFirstRootBlock
	bootFirstVsockTraffic
)

// bootTimeline correlates hypervisor/device milestones with the daemon's boot
// clock. origin is the daemon start time (or Prepare time for direct `run`). In
// a split worker it is reconstructed from UnixNano, so the total column uses
// wall time; vcpuStart is always local and retains Go's monotonic component,
// making the vCPU-relative column authoritative even if the wall clock moves.
type bootTimeline struct {
	origin time.Time
	out    io.Writer
	now    func() time.Time

	startOnce sync.Once
	started   atomic.Bool
	vcpuStart time.Time
	seen      atomic.Uint32
	writeMu   sync.Mutex
}

func newBootTimeline(origin time.Time, out io.Writer) *bootTimeline {
	if origin.IsZero() {
		return nil
	}
	if out == nil {
		out = os.Stdout
	}
	return &bootTimeline{origin: origin, out: out, now: time.Now}
}

// start records the instant the boot vCPU is about to enter the hypervisor.
// It is safe to call for every vCPU; only the boot vCPU's first call wins.
func (t *bootTimeline) start(phase string) {
	if t == nil {
		return
	}
	t.startOnce.Do(func() {
		now := t.now()
		t.vcpuStart = now
		t.write(phase, now, 0)
		t.started.Store(true)
	})
}

// mark records and prints only the first occurrence of a device milestone.
func (t *bootTimeline) mark(bit bootMilestone, phase string) {
	if t == nil || !t.started.Load() {
		return
	}
	mask := uint32(bit)
	for {
		seen := t.seen.Load()
		if seen&mask != 0 {
			return
		}
		if t.seen.CompareAndSwap(seen, seen|mask) {
			break
		}
	}
	now := t.now()
	t.write(phase, now, now.Sub(t.vcpuStart))
}

func (t *bootTimeline) write(phase string, now time.Time, fromVCPU time.Duration) {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	_, _ = fmt.Fprintf(t.out, "boot-timing: guest %-28s %9.3f ms total (vCPU +%9.3f ms)\n",
		phase, durationMillis(now.Sub(t.origin)), durationMillis(fromVCPU))
}

func durationMillis(d time.Duration) float64 {
	return float64(d) / float64(time.Millisecond)
}
