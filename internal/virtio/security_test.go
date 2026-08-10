//go:build linux || darwin

package virtio

// Regression tests for the guest-host trust boundary (see review.md): the
// guest controls virtqueue contents, MMIO register writes, and FUSE wire
// names — none of it may crash, exhaust, or escape the VMM.

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ejpir/gantry/internal/fusewire"

	"github.com/hanwen/go-fuse/v2/fuse"
)

type rejectingFuseHandler struct{ calls int }

func (h *rejectingFuseHandler) HandleRequest(_, _ [][]byte) (int, fuse.Status) {
	h.calls++
	return 0, fuse.OK
}

func TestVirtioFSRejectsMalformedRequestShape(t *testing.T) {
	tests := []struct {
		name        string
		descriptors []desc
	}{
		{
			name: "all writable",
			descriptors: []desc{
				{addr: ramBase + testDataAddr, len: 16, flags: vringDescFWrite},
			},
		},
		{
			name: "truncated header",
			descriptors: []desc{
				{addr: ramBase + testDataAddr, len: fusewire.InHeaderSize - 1, flags: vringDescFNext, next: 1},
				{addr: ramBase + testDataAddr + 64, len: 16, flags: vringDescFWrite},
			},
		},
		{
			name: "header starts in third input vector",
			descriptors: []desc{
				{addr: ramBase + testDataAddr, len: 1, flags: vringDescFNext, next: 1},
				{addr: ramBase + testDataAddr + 64, len: 1, flags: vringDescFNext, next: 2},
				{addr: ramBase + testDataAddr + 128, len: fusewire.InHeaderSize, flags: vringDescFNext, next: 3},
				{addr: ramBase + testDataAddr + 192, len: 16, flags: vringDescFWrite},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := new(rejectingFuseHandler)
			device, err := NewFS("malformed", handler, nil)
			if err != nil {
				t.Fatal(err)
			}
			mem := NewRAM(make([]byte, 2<<20), ramBase)
			core := NewCoreAt(device, mem, MMIOBaseArm64, MMIOIRQArm64, func(int, bool) {}, "fs")
			setupQueue(mem, core, virtioFSRequestQ, 8)
			for i, descriptor := range tt.descriptors {
				putDesc(mem, virtioFSRequestQ, uint16(i), descriptor.addr, descriptor.len, descriptor.flags, descriptor.next)
			}
			availPush(mem, virtioFSRequestQ, 0)
			core.MMIOWrite(0x050, virtioFSRequestQ)

			if handler.calls != 0 {
				t.Fatalf("malformed request reached handler %d times", handler.calls)
			}
			used, ok := usedPop(mem, virtioFSRequestQ)
			if !ok || used.id != 0 || used.len != 0 {
				t.Fatalf("used element = %+v, %v; want id 0 length 0", used, ok)
			}
		})
	}
}

// newTestBlkCore wires a virtio-blk device into 1 MiB of fake guest RAM.
func newTestBlkCore(t *testing.T) (*Core, *RAM) {
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

	if _, _, ok := core.availChain(0); ok {
		t.Fatal("oversized descriptor chain accepted")
	}
}

// Per-device protocol limits (chainLimiter): every device caps a chain's
// declared total far below guest RAM, so a hostile guest cannot size host
// allocations with descriptor lengths (review finding 2).
func TestDeviceChainLimitsImplemented(t *testing.T) {
	img := filepath.Join(t.TempDir(), "disk.img")
	if err := os.WriteFile(img, make([]byte, 1<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	blk, err := NewBlk(img, false)
	if err != nil {
		t.Fatal(err)
	}
	fsDev, err := newTestFS("limit", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	devs := map[string]Device{
		"blk":   blk,
		"net":   &Net{},
		"vsock": NewVsock(3, t.TempDir()),
		"fs":    fsDev,
		"rng":   NewRNG(),
		"rtc":   NewRTC(),
	}
	for name, dev := range devs {
		cl, ok := dev.(chainLimiter)
		if !ok {
			t.Errorf("%s does not implement chainLimiter", name)
			continue
		}
		l := cl.maxChainBytes(0)
		if l == 0 || l > 8<<20 {
			t.Errorf("%s chain limit %d out of sane range (0, 8 MiB]", name, l)
		}
	}
}

// A chain that stays inside guest RAM descriptor-by-descriptor but exceeds
// the device's protocol limit must be rejected before any buffer is sized
// from it. (8 MiB of fake RAM so the chain can legally exceed blk's
// 4 MiB cap.)
func TestChainExceedingDeviceLimitRejected(t *testing.T) {
	img := filepath.Join(t.TempDir(), "disk.img")
	if err := os.WriteFile(img, make([]byte, 1<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	blk, err := NewBlk(img, false)
	if err != nil {
		t.Fatal(err)
	}
	ram := make([]byte, 8<<20)
	mem := NewRAM(ram, ramBase)
	irqs := &irqRec{raised: map[int]bool{}}
	core := NewCoreAt(blk, mem, MMIOBaseArm64, MMIOIRQArm64, irqs.line, "blk")

	setupQueue(mem, core, 0, 8)
	// two 3 MiB descriptors: each valid RAM, total 6 MiB > blkMaxChainBytes
	putDesc(mem, 0, 0, ramBase+0x100000, 3<<20, vringDescFNext, 1)
	putDesc(mem, 0, 1, ramBase+0x400000, 3<<20, vringDescFWrite, 0)
	availPush(mem, 0, 0)

	if _, _, ok := core.availChain(0); ok {
		t.Fatal("chain exceeding blk protocol limit accepted")
	}
	// the notify path must drop it without allocating its declared size
	core.MMIOWrite(0x050, 0)

	// a chain under the limit still works
	putDesc(mem, 0, 2, ramBase+0x100000, 4096, vringDescFNext, 3)
	putDesc(mem, 0, 3, ramBase+0x200000, 4096, vringDescFWrite, 0)
	availPush(mem, 0, 2)
	if _, chain, ok := core.availChain(0); !ok || len(chain) != 2 {
		t.Fatalf("legitimate chain rejected: ok=%v len=%d", ok, len(chain))
	}
}
