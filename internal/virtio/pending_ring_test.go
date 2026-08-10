package virtio

import "testing"

func TestPendingRingWrapsInFIFOOrder(t *testing.T) {
	var q pendingRing[int]
	for i := range pendingRingCapacity {
		if _, ok := q.Push(i); !ok {
			t.Fatalf("push %d rejected before capacity", i)
		}
	}
	if _, ok := q.Push(pendingRingCapacity); ok {
		t.Fatal("push succeeded on full ring")
	}

	for want := range pendingRingCapacity / 2 {
		got, _, ok := q.Front()
		if !ok || *got != want {
			t.Fatalf("front = %v, %v; want %d, true", got, ok, want)
		}
		q.Pop()
	}
	for i := range pendingRingCapacity / 2 {
		if _, ok := q.Push(pendingRingCapacity + i); !ok {
			t.Fatalf("wrapped push %d rejected", i)
		}
	}
	for want := pendingRingCapacity / 2; want < pendingRingCapacity+pendingRingCapacity/2; want++ {
		got, _, ok := q.Front()
		if !ok || *got != want {
			t.Fatalf("wrapped front = %v, %v; want %d, true", got, ok, want)
		}
		q.Pop()
	}
	if q.Len() != 0 {
		t.Fatalf("length after drain = %d, want 0", q.Len())
	}
}

func TestNetPendingRingReleasesDeliveredPacket(t *testing.T) {
	var device Net
	if !device.enqueueRXFrame([]byte{1, 2, 3}) {
		t.Fatal("enqueue rejected")
	}
	packet, slot, ok := device.pending.Front()
	if !ok {
		t.Fatal("enqueued packet is missing")
	}
	if got := len(*packet); got != virtioNetHdrLen+3 {
		t.Fatalf("front packet length = %d, want %d", got, virtioNetHdrLen+3)
	}
	device.pending.Pop()
	if device.pending.slots[slot] != nil {
		t.Fatal("popped packet still retained by ring")
	}
}

func TestNetFullPendingQueueDropsWithoutAllocation(t *testing.T) {
	var device Net
	frame := make([]byte, 1500)
	for range pendingRingCapacity {
		if !device.enqueueRXFrame(frame) {
			t.Fatal("queue filled before its fixed capacity")
		}
	}
	if got := testing.AllocsPerRun(1000, func() {
		if device.enqueueRXFrame(frame) {
			t.Fatal("full queue accepted a frame")
		}
	}); got != 0 {
		t.Fatalf("full-queue drop allocated %.2f objects, want 0", got)
	}
}

func BenchmarkNetRXQueueFullDrop(b *testing.B) {
	var device Net
	frame := make([]byte, 1500)
	for range pendingRingCapacity {
		if !device.enqueueRXFrame(frame) {
			b.Fatal("queue filled before its fixed capacity")
		}
	}

	b.ReportAllocs()
	b.SetBytes(int64(len(frame)))
	b.ResetTimer()
	for b.Loop() {
		if device.enqueueRXFrame(frame) {
			b.Fatal("full queue accepted a frame")
		}
	}
}

func BenchmarkNetRXQueueEnqueue(b *testing.B) {
	var device Net
	frame := make([]byte, 1500)

	b.ReportAllocs()
	b.SetBytes(int64(len(frame)))
	b.ResetTimer()
	for b.Loop() {
		if !device.enqueueRXFrame(frame) {
			b.Fatal("empty queue rejected a frame")
		}
		device.pending.Pop()
	}
}
