package vmm

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
	"time"

	"github.com/ejpir/gantry/internal/virtio"
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
		mem:        virtio.NewRAM(ram, ramBase),
		bootTiming: timeline,
	}
	m.uart = newPL011(func(int, bool) {}, func(byte) {})
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
	m.handleMMIO(false, uartBase+0x18, data[:], 4)
	m.handleMMIO(false, root.Base(), data[:], 4)
	binary.LittleEndian.PutUint32(data[:], 0)
	m.handleMMIO(true, root.Base()+0x50, data[:], 4)
	binary.LittleEndian.PutUint32(data[:], 1)
	m.handleMMIO(true, vsock.Base()+0x50, data[:], 4)

	// Repeating every access must not emit duplicate first-occurrence lines.
	m.handleMMIO(false, uartBase+0x18, data[:], 4)
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
