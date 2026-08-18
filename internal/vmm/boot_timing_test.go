package vmm

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
	"time"

	"github.com/ejpir/gantry/internal/virtio"
	"github.com/ejpir/gantry/internal/vmm/boot"
	"github.com/ejpir/gantry/internal/vmm/devices"
)

func TestBootTimelineFirstOccurrence(t *testing.T) {
	origin := time.Unix(100, 0)
	now := origin.Add(10 * time.Millisecond)
	var out bytes.Buffer
	timeline := newBootTimeline(origin, &out)
	timeline.now = func() time.Time { return now }

	timeline.start("vCPU entered HVF")
	now = now.Add(25 * time.Millisecond)
	timeline.mark(bootFirstUART, "first UART access")
	timeline.mark(bootFirstUART, "first UART access")

	got := out.String()
	if strings.Count(got, "vCPU entered HVF") != 1 {
		t.Fatalf("start milestone count = %d, output:\n%s", strings.Count(got, "vCPU entered HVF"), got)
	}
	if strings.Count(got, "first UART access") != 1 {
		t.Fatalf("UART milestone count = %d, output:\n%s", strings.Count(got, "first UART access"), got)
	}
	for _, want := range []string{"10.000 ms total", "35.000 ms total", "vCPU +   25.000 ms"} {
		if !strings.Contains(got, want) {
			t.Errorf("output does not contain %q:\n%s", want, got)
		}
	}
}

func TestBootTimelineDisabled(t *testing.T) {
	var out bytes.Buffer
	timeline := newBootTimeline(time.Time{}, &out)
	timeline.start("vCPU entered HVF")
	timeline.mark(bootFirstUART, "first UART access")
	if out.Len() != 0 {
		t.Fatalf("disabled timeline output %q", out.String())
	}
}

func TestMachineBootMilestones(t *testing.T) {
	origin := time.Unix(200, 0)
	now := origin.Add(time.Millisecond)
	var out bytes.Buffer
	timeline := newBootTimeline(origin, &out)
	timeline.now = func() time.Time {
		current := now
		now = now.Add(time.Millisecond)
		return current
	}
	timeline.start("vCPU entered HVF")

	ram := make([]byte, 1<<20)
	m := &Machine{
		arch:       "arm64",
		mem:        virtio.NewRAM(ram, boot.RAMBase),
		bootTiming: timeline,
	}
	m.uart = devices.NewPL011(func(int, bool) {}, func(byte) {})
	root, err := m.addVirtio(virtio.NewRNG(), "blk")
	if err != nil {
		t.Fatal(err)
	}
	vsock, err := m.addVirtio(virtio.NewRNG(), "vsock")
	if err != nil {
		t.Fatal(err)
	}
	m.rootBlkCore = root
	m.vsockCore = vsock

	var data [4]byte
	m.handleMMIO(false, devices.PL011Base+0x18, data[:], 4)
	m.handleMMIO(false, root.Base(), data[:], 4)
	binary.LittleEndian.PutUint32(data[:], 0)
	m.handleMMIO(true, root.Base()+0x50, data[:], 4)
	binary.LittleEndian.PutUint32(data[:], 1)
	m.handleMMIO(true, vsock.Base()+0x50, data[:], 4)

	// Repeating every access must not emit duplicate first-occurrence lines.
	m.handleMMIO(false, devices.PL011Base+0x18, data[:], 4)
	m.handleMMIO(false, root.Base(), data[:], 4)
	binary.LittleEndian.PutUint32(data[:], 0)
	m.handleMMIO(true, root.Base()+0x50, data[:], 4)
	binary.LittleEndian.PutUint32(data[:], 1)
	m.handleMMIO(true, vsock.Base()+0x50, data[:], 4)

	got := out.String()
	for _, phase := range []string{
		"vCPU entered HVF",
		"first UART access",
		"first virtio-mmio access",
		"first root-block request",
		"first vsock traffic",
	} {
		if count := strings.Count(got, phase); count != 1 {
			t.Errorf("%q count = %d, output:\n%s", phase, count, got)
		}
	}
}

// Neither clock can explain a slow boot on its own: the guest's stops at
// every host-side wait, and the host's cannot tell execution from trapping.
// Milestones carry the vCPU's own counters so the two can be told apart.
func TestBootTimelineReportsVCPUStats(t *testing.T) {
	origin := time.Unix(300, 0)
	now := origin
	var out bytes.Buffer
	timeline := newBootTimeline(origin, &out)
	timeline.profile = true
	timeline.now = func() time.Time { return now }
	timeline.setRunStats(func() runStats {
		return runStats{
			Exits: 4200, WFI: 180, MMIO: 3600, Sysreg: 400, Other: 20,
			IdleWaits: 180, IdleCapped: 179, IdleBlocked: 180 * time.Millisecond,
		}
	})

	timeline.start("vCPU entered HVF")
	now = now.Add(200 * time.Millisecond)
	timeline.mark(bootFirstUART, "first UART access")

	got := out.String()
	want := "[exits 4200: wfi 180 mmio 3600 sysreg 400 other 20; " +
		"idle 180 waits, 180.000 ms blocked, 179 bounded]"
	if !strings.Contains(got, want) {
		t.Fatalf("milestone omits vCPU accounting:\n%s", got)
	}
}

func TestBootTimelineOmitsVCPUColumnWithoutBackend(t *testing.T) {
	origin := time.Unix(400, 0)
	var out bytes.Buffer
	timeline := newBootTimeline(origin, &out)
	timeline.now = func() time.Time { return origin }
	timeline.start("vCPU entered HVF")
	// A backend that has not run yet must not add an empty column either.
	timeline.setRunStats(func() runStats { return runStats{} })
	timeline.mark(bootFirstUART, "first UART access")
	if strings.Contains(out.String(), "exits") {
		t.Fatalf("vCPU column present with nothing to report:\n%s", out.String())
	}
}

func TestBootTimelineTracesEarlyExits(t *testing.T) {
	origin := time.Unix(500, 0)
	var out bytes.Buffer
	timeline := newBootTimeline(origin, &out)
	timeline.profile = true
	timeline.traceExit(1, 140*time.Millisecond, 1, 0x16, ", smccc fn 0x84000000")

	got := out.String()
	if !strings.Contains(got, "exit  #1") || !strings.Contains(got, "140.000 ms in the guest") {
		t.Fatalf("exit trace line = %q", got)
	}
	if !strings.Contains(got, "reason 1, ec 0x16, smccc fn 0x84000000") {
		t.Fatalf("exit trace omits classification: %q", got)
	}
}

func TestBootTimelineDisabledTracesNothing(t *testing.T) {
	var out bytes.Buffer
	timeline := newBootTimeline(time.Time{}, &out)
	timeline.traceExit(1, time.Second, 1, 0x24, ", pa 0x9000000")
	if out.Len() != 0 {
		t.Fatalf("disabled timeline traced %q", out.String())
	}
}

func TestBootTimelineBasicModeSkipsProfileWork(t *testing.T) {
	origin := time.Unix(550, 0)
	var out bytes.Buffer
	timeline := newBootTimeline(origin, &out)
	timeline.profile = false
	timeline.start("vCPU entered HVF")
	timeline.setRunStats(func() runStats { return runStats{Exits: 1} })
	timeline.traceExit(1, time.Second, 1, 0x24, ", pa 0x9000000")
	timeline.sample(0, 0xffff800080123456, 0xffff800080000000, "")
	if got := timeline.stampLine(nil); got != nil {
		t.Fatalf("basic timeline stamped console: %q", got)
	}
	got := out.String()
	if strings.Contains(got, "boot-profile:") || strings.Contains(got, "exit  #") || strings.Contains(got, "exits ") {
		t.Fatalf("basic timeline emitted profile output:\n%s", got)
	}
	if !strings.Contains(got, "vCPU entered HVF") {
		t.Fatalf("basic timeline omitted milestone:\n%s", got)
	}
}

func TestBootTimelineSampleResolvesKernelOffset(t *testing.T) {
	var out bytes.Buffer
	timeline := newBootTimeline(time.Unix(600, 0), &out)
	timeline.profile = true
	timeline.sample(0, 0xffff800080123456, 0xffff800080000000, " pa 0x40123456 code: d50b7b20")
	timeline.sample(1, 0x40200000, 0xffff800080000000, "") // below the text base

	got := out.String()
	if !strings.Contains(got, "cpu0 pc 0xffff800080123456 (kernel text +0x123456) pa 0x40123456 code: d50b7b20") {
		t.Errorf("kernel-space sample not resolved:\n%s", got)
	}
	if !strings.Contains(got, "cpu1 pc 0x40200000\n") {
		t.Errorf("sample below the text base must print the raw pc only:\n%s", got)
	}
}

// The sampler interrupts the guest, so it must stop once boot is over.
func TestBootTimelineBootComplete(t *testing.T) {
	origin := time.Unix(700, 0)
	timeline := newBootTimeline(origin, &bytes.Buffer{})
	timeline.now = func() time.Time { return origin }
	timeline.start("vCPU entered HVF")
	if timeline.bootComplete() {
		t.Fatal("boot reported complete before any milestone")
	}
	timeline.mark(bootFirstRootBlock, "first root-block request")
	if timeline.bootComplete() {
		t.Fatal("boot reported complete on an intermediate milestone")
	}
	timeline.mark(bootFirstVsockTraffic, "first vsock traffic")
	if !timeline.bootComplete() {
		t.Fatal("boot not reported complete at the last milestone")
	}
	var disabled *bootTimeline
	if disabled.bootComplete() {
		t.Fatal("disabled timeline reported boot complete")
	}
}

// Console lines carry a host stamp only while the boot window is open: the
// guest's own printk timestamps are zero until it registers a timer, so
// without one there is nothing to line a message up against the exit trace.
func TestBootTimelineStampsConsoleLines(t *testing.T) {
	origin := time.Unix(800, 0)
	now := origin
	timeline := newBootTimeline(origin, &bytes.Buffer{})
	timeline.profile = true
	timeline.now = func() time.Time { return now }

	if got := timeline.stampLine(nil); got != nil {
		t.Fatalf("stamped before the vCPU started: %q", got)
	}
	timeline.start("vCPU entered HVF")
	now = now.Add(150 * time.Millisecond)
	if got := string(timeline.stampLine(nil)); !strings.Contains(got, "host +  150.000 ms") {
		t.Fatalf("console stamp = %q", got)
	}

	timeline.mark(bootFirstVsockTraffic, "first vsock traffic")
	if got := timeline.stampLine(nil); got != nil {
		t.Fatalf("console still stamped after boot: %q", got)
	}
	var disabled *bootTimeline
	if got := disabled.stampLine(nil); got != nil {
		t.Fatalf("disabled timeline stamped: %q", got)
	}
}
