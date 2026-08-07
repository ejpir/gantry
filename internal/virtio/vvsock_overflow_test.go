package virtio

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// A hostile guest can ignore vsock flow control and blast RW packets while
// the host-side consumer is stalled: the per-connection outQ must stay
// bounded — by the advertised receive credit, and independently by hard
// byte/packet caps — and an overflowing connection must be reset, not
// buffered without limit (host memory DoS).
//
// Both tests connect to a net.Pipe whose host end is never read: pumpOut
// blocks exactly like a stalled broker/session consumer, so everything the
// guest sends piles up in outQ.

type vsockFloodRig struct {
	t    *testing.T
	mem  mem
	core *Core
	hdr  vsockHdr // established connection template (3:1111 -> 2:1025)
	// usedPop does not advance anything (it peeks at idx-1), so the rig
	// keeps its own cursors over the monotonic used-ring indices.
	rxSeen uint16
	txSeen uint16
}

func newVsockFloodRig(t *testing.T) *vsockFloodRig {
	t.Helper()
	hostSide, guestSide := net.Pipe()
	t.Cleanup(func() { hostSide.Close() })
	// guestSide intentionally unread: pumpOut blocks on its first write.

	vs := NewVsock(3, t.TempDir())
	vs.dial = func(port uint32) (net.Conn, error) { return guestSide, nil }
	ram := make([]byte, 2<<20)
	m := NewRAM(ram, ramBase)
	irqs := &irqRec{raised: map[int]bool{}}
	core := NewCoreAt(vs, m, MMIOBaseArm64+1*MMIOStrideArm64, MMIOIRQArm64+1, irqs.line, "vsock-flood")
	vs.core = core
	setupQueue(m, core, vsockQueueRx, 8)
	setupQueue(m, core, vsockQueueTx, 8)

	rig := &vsockFloodRig{t: t, mem: m, core: core,
		hdr: vsockHdr{srcCID: 3, dstCID: 2, srcPort: 1111, dstPort: 1025, typ: vsockTypeStream, bufAlloc: 8192}}
	rig.postRxBuf(0)
	rig.postRxBuf(2)
	rig.postRxBuf(4)
	rig.postRxBuf(6)

	// Establish: REQUEST -> RESPONSE (host socket accepted, conn created).
	rig.sendRaw(rig.hdr.marshal(), vsockOpRequest, 0)
	e, ok := rig.nextUsed(vsockQueueRx, time.Now().Add(15*time.Second))
	if !ok {
		t.Fatal("no RESPONSE in rx used ring")
	}
	buf := make([]byte, vsockHdrLen)
	m.readAt(ramBase+testDataAddr+uint64(e.id)*0x100, buf)
	if resp := parseVsockHdr(buf); resp.op != vsockOpResponse {
		t.Fatalf("expected RESPONSE, got %+v", resp)
	}
	rig.postRxBuf(uint16(e.id))
	return rig
}

func (r *vsockFloodRig) postRxBuf(head uint16) {
	putDesc(r.mem, 0, head, ramBase+testDataAddr+uint64(head)*0x100, vsockHdrLen, vringDescFNext|vringDescFWrite, head+1)
	putDesc(r.mem, 0, head+1, ramBase+testDataAddr+0x800+uint64(head)*0x100, 1024, vringDescFWrite, 0)
	availPush(r.mem, 0, head)
	r.core.MMIOWrite(0x050, vsockQueueRx)
}

// nextUsed returns the first used-ring element the rig has not consumed
// yet, waiting up to deadline for one to appear.
func (r *vsockFloodRig) nextUsed(qn uint32, deadline time.Time) (usedElem, bool) {
	seen := &r.rxSeen
	if qn == vsockQueueTx {
		seen = &r.txSeen
	}
	for {
		if n := usedIndex(r.mem, qn); *seen < n {
			e := usedAt(r.mem, qn, *seen)
			*seen++
			return e, true
		}
		if time.Now().After(deadline) {
			return usedElem{}, false
		}
		time.Sleep(time.Millisecond)
	}
}

// sendRaw posts one guest->host packet (hdr + payload in a single
// descriptor) on the established connection and waits for the device to
// consume it from the tx ring.
func (r *vsockFloodRig) sendRaw(msg []byte, op uint16, payloadLen int) {
	binary.LittleEndian.PutUint32(msg[24:], uint32(payloadLen))
	msg[30], msg[31] = byte(op), 0
	r.mem.writeAt(ramBase+testDataAddr, msg)
	putDesc(r.mem, 1, 0, ramBase+testDataAddr, uint32(len(msg)), 0, 0)
	availPush(r.mem, 1, 0)
	r.core.MMIOWrite(0x050, vsockQueueTx)
	if _, ok := r.nextUsed(vsockQueueTx, time.Now().Add(15*time.Second)); !ok {
		r.t.Fatal("device never consumed tx descriptor")
	}
}

func (r *vsockFloodRig) sendRW(payload []byte) {
	msg := append(r.hdr.marshal(), payload...)
	r.sendRaw(msg, vsockOpRW, len(payload))
}

// pollRST reports whether an RST has appeared among the rx used elements
// not yet consumed, replenishing buffers so later control packets flush.
func (r *vsockFloodRig) pollRST() bool {
	for {
		e, ok := r.nextUsed(vsockQueueRx, time.Now())
		if !ok {
			return false
		}
		buf := make([]byte, vsockHdrLen)
		r.mem.readAt(ramBase+testDataAddr+uint64(e.id)*0x100, buf)
		op := parseVsockHdr(buf).op
		r.postRxBuf(uint16(e.id))
		if op == vsockOpRST {
			return true
		}
	}
}

func TestVsockGuestBeyondCreditGetsRST(t *testing.T) {
	rig := newVsockFloodRig(t)
	payload := make([]byte, 1024)
	// vsockBufAlloc is 64 KiB and pumpOut is blocked (rxCnt stays 0):
	// the 65th 1 KiB RW crosses the advertised credit and must reset.
	for i := 0; i < 80; i++ {
		rig.sendRW(payload)
		if rig.pollRST() {
			if i < 63 {
				t.Fatalf("RST after only %d KiB — credit bound fired early", i+1)
			}
			return
		}
	}
	t.Fatal("guest sent 80 KiB beyond a stalled 64 KiB credit window without RST")
}

func TestVsockPacketFloodGetsRST(t *testing.T) {
	rig := newVsockFloodRig(t)
	// 1-byte RWs stay well inside byte credit; the packet cap must trip.
	for i := 0; i < vsockOutQMaxPackets+64; i++ {
		rig.sendRW([]byte{byte(i)})
		if rig.pollRST() {
			if i < vsockOutQMaxPackets-2 {
				t.Fatalf("RST after only %d packets — cap fired early", i+1)
			}
			return
		}
	}
	t.Fatalf("guest queued %d packets on a stalled connection without RST", vsockOutQMaxPackets+64)
}
