package main

// Regression tests for the guest-host trust boundary (see review.md): the
// guest controls virtqueue contents, MMIO register writes, and FUSE wire
// names — none of it may crash, exhaust, or escape the VMM.

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// newTestBlkCore wires a virtio-blk device into 1 MiB of fake guest RAM.
func newTestBlkCore(t *testing.T) (*virtioMMIOCore, guestMem) {
	t.Helper()
	img := filepath.Join(t.TempDir(), "disk.img")
	if err := os.WriteFile(img, make([]byte, 1<<20), 0o644); err != nil {
		t.Fatal(err)
	}
	blk, err := newVirtioBlk(img, false)
	if err != nil {
		t.Fatal(err)
	}
	ram := make([]byte, 2<<20)
	mem := &ramMem{ram: ram, base: ramBase}
	irqs := &irqRec{raised: map[int]bool{}}
	core := newVirtioMMIOAt(blk, mem, virtioMMIOBase, virtioMMIOIRQ, irqs.line, "blk")
	blk.core = core
	return core, mem
}

// QueueNum=0 used to divide by zero in the ring index math; QueueNum larger
// than QueueNumMax must not arm the ring either.
func TestQueueNumClamp(t *testing.T) {
	core, mem := newTestBlkCore(t)

	for _, num := range []uint32{0, 1 << 16, 0xdeadbeef} {
		core.mmioWrite(0x030, 0)   // QueueSel
		core.mmioWrite(0x038, num) // QueueNum (malicious)
		core.mmioWrite(0x044, 1)   // QueueReady
		core.mmioWrite(0x050, 0)   // QueueNotify — must not panic
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
	core.mmioWrite(0x050, 0) // notify: chain must be rejected, no 4 GiB alloc

	if _, _, ok := core.availChain(&core.queues[0]); ok {
		t.Fatal("oversized descriptor chain accepted")
	}
}

// Sandbox names feed filepath.Join + os.RemoveAll: path traversal out of the
// sandbox root must be rejected before any subcommand sees the name.
func TestSandboxNameTraversal(t *testing.T) {
	for _, bad := range []string{"", ".", "..", "../victim", "a/b", `a\b`, "a b", "a\u0000b"} {
		if validSandboxName(bad) {
			t.Fatalf("validSandboxName(%q) = true", bad)
		}
	}
	for _, good := range []string{"dev", "my-vm.2_test", "..ok"} {
		if !validSandboxName(good) {
			t.Fatalf("validSandboxName(%q) = false", good)
		}
	}
}

// The broker frames the task exit status as a NUL-delimited trailer; the
// attach client must strip it from the terminal stream and surface it.
func TestExitTrailer(t *testing.T) {
	in := "shell output\r\n" + exitTrailerPrefix + "42\x00"
	var out bytes.Buffer
	status := copyStrippingExitTrailer(&out, bytes.NewReader([]byte(in)))
	if status != 42 {
		t.Fatalf("status = %d, want 42", status)
	}
	if out.String() != "shell output\r\n" {
		t.Fatalf("output = %q, trailer not stripped", out.String())
	}

	// no trailer: plain pass-through, status 0
	out.Reset()
	status = copyStrippingExitTrailer(&out, bytes.NewReader([]byte("plain")))
	if status != 0 || out.String() != "plain" {
		t.Fatalf("plain stream: status=%d out=%q", status, out.String())
	}
}
