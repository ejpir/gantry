package virtio

import "testing"

func TestVsockPendingQueueReservesControlCapacity(t *testing.T) {
	var device Vsock
	data := vsockPkt{hdr: vsockHdr{op: vsockOpRW}, payload: []byte{1}}
	for i := 0; i < vsockMaxPending-vsockControlReserve; i++ {
		if !device.queuePending(data) {
			t.Fatalf("data packet %d rejected before data limit", i)
		}
	}
	if device.queuePending(data) {
		t.Fatal("data consumed reserved control capacity")
	}

	control := vsockPkt{hdr: vsockHdr{op: vsockOpRST}}
	for i := 0; i < vsockControlReserve; i++ {
		control.hdr.srcPort = uint32(i + 1)
		if !device.queuePending(control) {
			t.Fatalf("control packet %d rejected inside reserve", i)
		}
	}
	if got := device.pending.Len(); got != vsockMaxPending {
		t.Fatalf("pending length = %d, want %d", got, vsockMaxPending)
	}
	if device.queuePending(control) {
		t.Fatal("control packet exceeded physical queue bound")
	}
}

func TestVsockPendingQueueCoalescesCreditUpdates(t *testing.T) {
	var device Vsock
	packet := vsockPkt{hdr: vsockHdr{
		srcPort: 1025,
		dstPort: 1111,
		op:      vsockOpCreditUpdate,
	}}
	for i := range 10_000 {
		packet.hdr.fwdCnt = uint32(i)
		if !device.queuePending(packet) {
			t.Fatalf("credit update %d rejected", i)
		}
	}
	if got := device.pending.Len(); got != 1 {
		t.Fatalf("pending credit updates = %d, want 1", got)
	}
	got, _, ok := device.pending.Front()
	if !ok {
		t.Fatal("coalesced credit update is missing")
	}
	if want := uint32(9_999); got.hdr.fwdCnt != want {
		t.Fatalf("coalesced fwd_cnt = %d, want %d", got.hdr.fwdCnt, want)
	}
	device.popPending()
	if len(device.pendingCredit) != 0 {
		t.Fatalf("credit index retained %d stale entries", len(device.pendingCredit))
	}
}

func TestVsockFullPendingQueueRejectsWithoutAllocation(t *testing.T) {
	var device Vsock
	packet := vsockPkt{hdr: vsockHdr{op: vsockOpRST}}
	for range vsockMaxPending {
		if !device.queuePending(packet) {
			t.Fatal("control queue filled before its fixed capacity")
		}
	}
	if got := testing.AllocsPerRun(1000, func() {
		if device.queuePending(packet) {
			t.Fatal("full control queue accepted a packet")
		}
	}); got != 0 {
		t.Fatalf("full control-queue rejection allocated %.2f objects, want 0", got)
	}
}

func TestVsockPeerCreditUsesForwardedBytesAndWraps(t *testing.T) {
	tests := []struct {
		name                   string
		allocated, sent, freed uint32
		want                   uint32
	}{
		{name: "empty window", allocated: 64, want: 64},
		{name: "window exhausted", allocated: 64, sent: 64, want: 0},
		{name: "consumption restores credit", allocated: 64, sent: 64, freed: 20, want: 20},
		{name: "counter wrap", allocated: 10, sent: 2, freed: ^uint32(0) - 1, want: 6},
		{name: "peer cannot free unsent bytes", allocated: 64, sent: 10, freed: 11, want: 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			conn := vsockConn{
				peerBufAlloc: test.allocated,
				txCnt:        test.sent,
				peerFwdCnt:   test.freed,
			}
			if got := conn.peerCredit(); got != test.want {
				t.Fatalf("peerCredit() = %d, want %d", got, test.want)
			}
		})
	}
}
