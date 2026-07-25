//go:build linux || darwin

package virtio

// Regression tests for the guest-host trust boundary (see review.md): the
// guest controls virtqueue contents, MMIO register writes, and FUSE wire
// names — none of it may crash, exhaust, or escape the VMM.

import (
	"os"
	"path/filepath"
	"testing"
)

// newTestBlkCore wires a virtio-blk device into 1 MiB of fake guest RAM.
func newTestBlkCore(t *testing.T) (*Core, mem) {
	t.Helper()
	img := filepath.Join(t.TempDir(), "disk.img")
	if err := os.WriteFile(img, make([]byte, 1<<20), 0o644); err != nil {
		t.Fatal(err)
	}
	blk, err := NewBlk(img, false)
	if err != nil {
		t.Fatal(err)
	}
	ram := make([]byte, 2<<20)
	mem := NewRAM(ram, ramBase)
	irqs := &irqRec{raised: map[int]bool{}}
	core := NewCoreAt(blk, mem, MMIOBaseArm64, MMIOIRQArm64, irqs.line, "blk")
	blk.core = core
	return core, mem
}

// QueueNum=0 used to divide by zero in the ring index math; QueueNum larger
// than QueueNumMax must not arm the ring either.
func TestQueueNumClamp(t *testing.T) {
	core, mem := newTestBlkCore(t)

	for _, num := range []uint32{0, 1 << 16, 0xdeadbeef} {
		core.MMIOWrite(0x030, 0)   // QueueSel
		core.MMIOWrite(0x038, num) // QueueNum (malicious)
		core.MMIOWrite(0x044, 1)   // QueueReady
		core.MMIOWrite(0x050, 0)   // QueueNotify — must not panic
		if core.queues[0].ready {
			t.Fatalf("queue armed with num=%d", num)
		}
	}
	// a valid size still works
	setupQueue(mem, core, 0, 8)
	if !core.queues[0].ready || core.queues[0].num != 8 {
		t.Fatalf("valid queue setup broken: %+v", core.queues[0])
	}
}

// A descriptor with a guest-chosen length near 4 GiB used to make the host
// allocate it outright; descAt now rejects anything beyond RAM size.
func TestGiantDescriptorRejected(t *testing.T) {
	core, mem := newTestBlkCore(t)
	setupQueue(mem, core, 0, 8)

	putDesc(mem, 0, 0, ramBase+testDataAddr, 0xfffff000, vringDescFWrite, 0) // ~4 GiB
	availPush(mem, 0, 0)
	core.MMIOWrite(0x050, 0) // notify: chain must be rejected, no 4 GiB alloc

	if _, _, ok := core.availChain(&core.queues[0]); ok {
		t.Fatal("oversized descriptor chain accepted")
	}
}
