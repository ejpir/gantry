//go:build linux || darwin

package virtio

import (
	"net"
	"testing"
	"time"
)

// Regression test for the rx-queue livelock found via a SIGQUIT dump of a
// stuck sandbox: a pending host->guest frame larger than every rx buffer
// the guest posts was retained at the head of the pending FIFO forever.
// Every consumed buffer came back with len 0, the guest driver reposted it
// and kicked the queue, and tryFlush — holding core.mu — consumed it again:
// a notify storm that wedged the whole vsock device while pinning a host
// core in MMIOWrite -> tryFlush.
//
// The device may retry while a later buffer could still be bigger, but
// after a full ring of failures it must drop the packet and RST the
// connection so the FIFO and the guest application make progress again.
func TestVsockUndeliverableRxPacketGetsDropped(t *testing.T) {
	hostSide, guestSide := net.Pipe()
	t.Cleanup(func() { _ = hostSide.Close() })

	dev := NewVsock(3, t.TempDir())
	dev.dial = func(uint32) (net.Conn, error) { return guestSide, nil }
	mem := NewRAM(make([]byte, 2<<20), ramBase)
	irqs := &irqRec{raised: map[int]bool{}}
	core := NewCoreAt(dev, mem, MMIOBaseArm64+MMIOStrideArm64, MMIOIRQArm64+1, irqs.line, "vsock-rx-miss")
	dev.core = core
	t.Cleanup(func() { _ = dev.Close() })
	setupQueue(mem, core, vsockQueueRx, 8)
	setupQueue(mem, core, vsockQueueTx, 8)

	// One rx chain: 44-byte header descriptor + 1024-byte payload
	// descriptor = 1068 bytes of capacity — big enough for control frames
	// (RESPONSE/RST), too small for the 2048-byte payload sent below.
	postSmallRx := func(head uint16) {
		putDesc(mem, 0, head, ramBase+testDataAddr+uint64(head)*0x200, vsockHdrLen, vringDescFNext|vringDescFWrite, head+1)
		putDesc(mem, 0, head+1, ramBase+testDataAddr+0x1000+uint64(head)*0x200, 1024, vringDescFWrite, 0)
		availPush(mem, 0, head)
		core.MMIOWrite(0x050, vsockQueueRx)
	}

	var rxSeen, txSeen uint16
	nextUsed := func(qn uint32, deadline time.Time) (usedElem, bool) {
		seen := &rxSeen
		if qn == vsockQueueTx {
			seen = &txSeen
		}
		for {
			if n := usedIndex(mem, qn); *seen < n {
				e := usedAt(mem, qn, *seen)
				*seen++
				return e, true
			}
			if time.Now().After(deadline) {
				return usedElem{}, false
			}
			time.Sleep(time.Millisecond)
		}
	}

	// Establish a stream connection (REQUEST 3:1111 -> 2:1025); the host's
	// RESPONSE lands in the posted rx buffer.
	postSmallRx(0)
	req := vsockHdr{
		srcCID: 3, dstCID: vsockHostCID,
		srcPort: 1111, dstPort: 1025,
		typ: vsockTypeStream, op: vsockOpRequest,
		bufAlloc: 8192,
	}
	msg := req.marshal()
	_ = mem.writeAt(ramBase+testDataAddr+0x2000, msg)
	putDesc(mem, 1, 0, ramBase+testDataAddr+0x2000, uint32(len(msg)), 0, 0)
	availPush(mem, 1, 0)
	core.MMIOWrite(0x050, vsockQueueTx)
	if _, ok := nextUsed(vsockQueueTx, time.Now().Add(15*time.Second)); !ok {
		t.Fatal("device never consumed the REQUEST tx descriptor")
	}
	e, ok := nextUsed(vsockQueueRx, time.Now().Add(15*time.Second))
	if !ok {
		t.Fatal("no RESPONSE in rx used ring")
	}
	buf := make([]byte, vsockHdrLen)
	_ = mem.readAt(ramBase+testDataAddr+uint64(e.id)*0x200, buf)
	if resp := parseVsockHdr(buf); resp.op != vsockOpResponse {
		t.Fatalf("expected RESPONSE, got %+v", resp)
	}

	// The host side sends a 2048-byte payload: pumpHost queues one RW
	// packet whose 2092-byte frame cannot fit the 1068-byte buffers this
	// guest keeps posting. Like the stock Linux driver, the test takes
	// every len-0 used buffer back and reposts it with a fresh notify.
	postSmallRx(2)
	if _, err := hostSide.Write(make([]byte, 2048)); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(15 * time.Second)
	misses := 0
	for {
		e, ok := nextUsed(vsockQueueRx, deadline)
		if !ok {
			t.Fatalf("no RST after %d reposts — packet never dropped (rx livelock)", misses)
		}
		if e.len == 0 {
			misses++
			postSmallRx(uint16(e.id)) // guest refill + kick
			continue
		}
		buf := make([]byte, vsockHdrLen)
		_ = mem.readAt(ramBase+testDataAddr+uint64(e.id)*0x200, buf)
		if got := parseVsockHdr(buf); got.op != vsockOpRST {
			t.Fatalf("expected RST after undeliverable packet, got op=%d len=%d", got.op, e.len)
		}
		if misses <= 8 {
			t.Fatalf("RST after only %d len-0 retries — retry bound regressed", misses)
		}
		break
	}

	core.mu.Lock()
	connsLeft := len(dev.conns)
	pendingLeft := dev.pending.Len()
	streak := dev.rxMissStreak
	core.mu.Unlock()
	if connsLeft != 0 || pendingLeft != 0 || streak != 0 {
		t.Fatalf("after drop: conns=%d pending=%d streak=%d, want all zero", connsLeft, pendingLeft, streak)
	}
}
