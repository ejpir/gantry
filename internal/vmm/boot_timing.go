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
	stats     atomic.Pointer[runStatsFunc]
}

// runStats is what a backend can say about the vCPUs themselves between two
// milestones. The guest's own clock cannot answer it: printk timestamps do
// not start until the kernel registers a timer, so everything before that —
// and every host-side wait, which does not advance guest execution at all —
// is invisible from inside. Exit classes separate "the guest is running and
// we never see it" from "the guest keeps trapping out to us" from "the guest
// is idle and we are the ones sleeping".
type runStats struct {
	Exits       uint64 // hv_vcpu_run returns
	WFI         uint64 // guest idled
	MMIO        uint64 // data aborts routed to the device model
	Sysreg      uint64 // MSR/MRS traps
	Other       uint64 // PSCI, vtimer, cancellations, everything else
	IdleWaits   uint64
	IdleCapped  uint64 // idle waits released by the bound, not by a wakeup
	IdleBlocked time.Duration
}

type runStatsFunc func() runStats

// setRunStats installs the backend's counters. Safe before or after the
// vCPUs start; milestones simply omit the column until it is set.
func (t *bootTimeline) setRunStats(report runStatsFunc) {
	if t == nil || report == nil {
		return
	}
	t.stats.Store(&report)
}

// statsSuffix renders the vCPU column, empty when no backend reports one.
func (t *bootTimeline) statsSuffix() string {
	report := t.stats.Load()
	if report == nil {
		return ""
	}
	s := (*report)()
	if s.Exits == 0 && s.IdleWaits == 0 {
		return ""
	}
	return fmt.Sprintf("  [exits %d: wfi %d mmio %d sysreg %d other %d; idle %d waits, %.3f ms blocked, %d bounded]",
		s.Exits, s.WFI, s.MMIO, s.Sysreg, s.Other,
		s.IdleWaits, durationMillis(s.IdleBlocked), s.IdleCapped)
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

// traceExit records one early hv_vcpu_run round trip. The window between the
// vCPU entering the hypervisor and the guest's first device access is
// otherwise unattributable: the guest's clock does not run before it programs
// a timer, so a long first entry (hypervisor-side setup, stage-2 population)
// and genuinely slow guest code look identical from the outside. Only the
// first few exits are traced — enough to place that gap, cheap enough to
// leave in the diagnostic path.
func (t *bootTimeline) traceExit(index int, ran time.Duration, reason uint32, ec uint64, detail string) {
	if t == nil {
		return
	}
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	_, _ = fmt.Fprintf(t.out, "boot-timing: exit  #%-3d ran %9.3f ms in the guest (reason %d, ec %#x%s)\n",
		index, durationMillis(ran), reason, ec, detail)
}

// sample records where the guest was when it was interrupted. Long stretches
// inside hv_vcpu_run are pure in-guest time: no exit says what the guest was
// doing, and the guest's own clock does not run yet, so the only way to
// attribute them is to stop the guest and read its PC.
func (t *bootTimeline) sample(cpu int, pc, textBase uint64, detail string) {
	if t == nil {
		return
	}
	where := ""
	if pc >= textBase {
		where = fmt.Sprintf(" (kernel text +%#x)", pc-textBase)
	}
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	_, _ = fmt.Fprintf(t.out, "boot-profile: cpu%d pc %#x%s%s\n", cpu, pc, where, detail)
}

// stampLine prefixes a console line with the host time since the vCPU
// entered the hypervisor — the same clock the exit trace and the milestones
// use, so a guest message can be placed against them. Off unless the
// timeline is enabled, and it retires with the rest of the boot
// diagnostics so a long-running guest's console stays untouched.
func (t *bootTimeline) stampLine(dst []byte) []byte {
	if t == nil || !t.started.Load() || t.bootComplete() {
		return dst
	}
	return fmt.Appendf(dst, "[host +%9.3f ms] ", durationMillis(t.now().Sub(t.vcpuStart)))
}

// bootComplete reports the last milestone having passed, so diagnostics that
// only make sense during boot can retire themselves.
func (t *bootTimeline) bootComplete() bool {
	return t != nil && t.seen.Load()&uint32(bootFirstVsockTraffic) != 0
}

// note records a host-side phase that happens before the guest runs, where
// the vCPU-relative column has no meaning; the duration of the phase itself
// takes its place.
func (t *bootTimeline) note(phase string, start, end time.Time) {
	if t == nil {
		return
	}
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	_, _ = fmt.Fprintf(t.out, "boot-timing: host  %-28s %9.3f ms total (took %9.3f ms)\n",
		phase, durationMillis(end.Sub(t.origin)), durationMillis(end.Sub(start)))
}

func (t *bootTimeline) write(phase string, now time.Time, fromVCPU time.Duration) {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	_, _ = fmt.Fprintf(t.out, "boot-timing: guest %-28s %9.3f ms total (vCPU +%9.3f ms)%s\n",
		phase, durationMillis(now.Sub(t.origin)), durationMillis(fromVCPU), t.statsSuffix())
}

func durationMillis(d time.Duration) float64 {
	return float64(d) / float64(time.Millisecond)
}
