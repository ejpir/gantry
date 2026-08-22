//go:build linux || darwin

package virtio

import (
	"encoding/binary"
	"errors"
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
	mem  *RAM
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
	t.Cleanup(func() { _ = hostSide.Close() })
	// guestSide intentionally unread: pumpOut blocks on its first write.

	vs := NewVsock(3, t.TempDir())
	vs.dial = func(port uint32) (net.Conn, error) { return guestSide, nil }
	ram := make([]byte, 2<<20)
	m := NewRAM(ram, ramBase)
	irqs := &irqRec{raised: map[int]bool{}}
	core := NewCoreAt(vs, m, MMIOBaseArm64+1*MMIOStrideArm64, MMIOIRQArm64+1, irqs.line, "vsock-flood")
	vs.core = core
	t.Cleanup(func() { _ = vs.Close() })
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
	_ = m.readAt(ramBase+testDataAddr+uint64(e.id)*0x100, buf)
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
	_ = r.mem.writeAt(ramBase+testDataAddr, msg)
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
		_ = r.mem.readAt(ramBase+testDataAddr+uint64(e.id)*0x100, buf)
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

type vsockNoRXRig struct {
	t      *testing.T
	device *Vsock
	mem    *RAM
	core   *Core
}

func newVsockNoRXRig(t *testing.T) *vsockNoRXRig {
	t.Helper()
	device := NewVsock(3, t.TempDir())
	device.dial = func(uint32) (net.Conn, error) { return nil, net.ErrClosed }
	memory := NewRAM(make([]byte, 2<<20), ramBase)
	irqs := &irqRec{raised: map[int]bool{}}
	core := NewCoreAt(device, memory, MMIOBaseArm64+MMIOStrideArm64, MMIOIRQArm64+1, irqs.line, "vsock-no-rx")
	device.core = core
	setupQueue(memory, core, vsockQueueTx, 8)
	t.Cleanup(func() { _ = device.Close() })
	return &vsockNoRXRig{t: t, device: device, mem: memory, core: core}
}

func (r *vsockNoRXRig) send(op uint16, sequence uint32) {
	r.t.Helper()
	hdr := vsockHdr{
		srcCID:   3,
		dstCID:   vsockHostCID,
		srcPort:  10_000 + sequence,
		dstPort:  1025,
		typ:      vsockTypeStream,
		op:       op,
		bufAlloc: vsockBufAlloc,
	}
	if op == vsockOpRequest {
		// Force the invalid-REQUEST RST path without opening a host socket.
		hdr.dstCID = vsockHostCID + 1
	}
	frame := make([]byte, vsockHdrLen)
	hdr.marshalTo(frame)
	if err := r.mem.writeAt(ramBase+testDataAddr, frame); err != nil {
		r.t.Fatal(err)
	}
	putDesc(r.mem, vsockQueueTx, 0, ramBase+testDataAddr, uint32(len(frame)), 0, 0)
	availPush(r.mem, vsockQueueTx, 0)
	r.core.MMIOWrite(0x050, vsockQueueTx)
}

func TestVsockInvalidPacketFloodWithoutRXIsBounded(t *testing.T) {
	for _, op := range []uint16{vsockOpRequest, vsockOpRW} {
		t.Run(map[uint16]string{vsockOpRequest: "request", vsockOpRW: "rw"}[op], func(t *testing.T) {
			rig := newVsockNoRXRig(t)
			for i := range vsockMaxPending * 4 {
				rig.send(op, uint32(i))
			}
			if got := rig.device.pending.Len(); got != vsockMaxPending {
				t.Fatalf("pending RST packets = %d, want strict cap %d", got, vsockMaxPending)
			}
		})
	}
}

func TestVsockCreditRequestFloodWithoutRXCoalesces(t *testing.T) {
	rig := newVsockNoRXRig(t)
	host, peer := net.Pipe()
	t.Cleanup(func() { _ = peer.Close() })
	key := connKey(1111, 1025)
	rig.device.conns[key] = &vsockConn{
		key: key, nc: host, established: true,
		outSig: make(chan struct{}, 1), done: make(chan struct{}),
	}
	for i := range vsockMaxPending * 4 {
		// Keep the same tuple so every cumulative update replaces its queued
		// predecessor while the guest withholds receive descriptors.
		hdr := vsockHdr{
			srcCID: 3, dstCID: vsockHostCID,
			srcPort: 1111, dstPort: 1025,
			typ: vsockTypeStream, op: vsockOpCreditReq,
			bufAlloc: vsockBufAlloc, fwdCnt: uint32(i),
		}
		frame := make([]byte, vsockHdrLen)
		hdr.marshalTo(frame)
		if err := rig.mem.writeAt(ramBase+testDataAddr, frame); err != nil {
			t.Fatal(err)
		}
		putDesc(rig.mem, vsockQueueTx, 0, ramBase+testDataAddr, uint32(len(frame)), 0, 0)
		availPush(rig.mem, vsockQueueTx, 0)
		rig.core.MMIOWrite(0x050, vsockQueueTx)
	}
	if got := rig.device.pending.Len(); got != 1 {
		t.Fatalf("pending CREDIT_UPDATE packets = %d, want 1", got)
	}
}

func TestVsockPumpEOFRSTWithoutRXIsBounded(t *testing.T) {
	rig := newVsockNoRXRig(t)
	packet := vsockPkt{hdr: vsockHdr{op: vsockOpRST}}
	for i := 0; i < vsockMaxPending-1; i++ {
		if !rig.device.queuePending(packet) {
			t.Fatalf("prefill packet %d rejected", i)
		}
	}

	pumpEOF := func(srcPort uint32) {
		host, peer := net.Pipe()
		if err := peer.Close(); err != nil {
			t.Fatal(err)
		}
		key := connKey(srcPort, 1025)
		conn := &vsockConn{
			key: key, nc: host, established: true,
			outSig: make(chan struct{}, 1), done: make(chan struct{}),
		}
		rig.device.conns[key] = conn
		rig.device.pumpHost(conn, srcPort, 1025)
	}

	pumpEOF(1111)
	if got := rig.device.pending.Len(); got != vsockMaxPending {
		t.Fatalf("pending after first EOF = %d, want %d", got, vsockMaxPending)
	}
	pumpEOF(1112)
	if got := rig.device.pending.Len(); got != vsockMaxPending {
		t.Fatalf("pending after overflow EOF = %d, want strict cap %d", got, vsockMaxPending)
	}
}

func TestVsockInjectConnRejectsFullGuestQueue(t *testing.T) {
	rig := newVsockNoRXRig(t)
	packet := vsockPkt{hdr: vsockHdr{op: vsockOpRST}}
	for range vsockMaxPending {
		if !rig.device.queuePending(packet) {
			t.Fatal("control queue filled before its fixed capacity")
		}
	}

	host, peer := net.Pipe()
	defer func() { _ = host.Close() }()
	defer func() { _ = peer.Close() }()
	wantPort := rig.device.nextHostPort
	if err := rig.device.InjectConn(1026, host); !errors.Is(err, errVsockPendingFull) {
		t.Fatalf("InjectConn error = %v, want %v", err, errVsockPendingFull)
	}
	if rig.device.nextHostPort != wantPort {
		t.Fatalf("next host port advanced from %d to %d after rejection", wantPort, rig.device.nextHostPort)
	}
	if len(rig.device.conns) != 0 {
		t.Fatalf("rejected injection retained %d connections", len(rig.device.conns))
	}
	if got := rig.device.pending.Len(); got != vsockMaxPending {
		t.Fatalf("pending after rejected injection = %d, want %d", got, vsockMaxPending)
	}
}

func TestVsockCreditUpdatesRestoreMultipleSendWindows(t *testing.T) {
	device := NewVsock(3, t.TempDir())
	memory := NewRAM(make([]byte, 2<<20), ramBase)
	irqs := &irqRec{raised: map[int]bool{}}
	core := NewCoreAt(device, memory, MMIOBaseArm64+MMIOStrideArm64, MMIOIRQArm64+1, irqs.line, "vsock-credit")
	setupQueue(memory, core, vsockQueueRx, 8)
	setupQueue(memory, core, vsockQueueTx, 8)

	host, peer := net.Pipe()
	t.Cleanup(func() { _ = peer.Close() })
	key := connKey(1111, 1025)
	conn := &vsockConn{
		key: key, nc: host, established: true,
		peerBufAlloc: 4, txCnt: 4,
		outSig: make(chan struct{}, 1), done: make(chan struct{}),
	}
	device.conns[key] = conn
	t.Cleanup(func() { _ = device.Close() })

	for window := uint32(1); window <= 3; window++ {
		packet := vsockPkt{
			hdr: vsockHdr{
				srcCID: vsockHostCID, dstCID: device.guestCID,
				srcPort: 1025, dstPort: 1111,
				typ: vsockTypeStream, op: vsockOpRW,
				bufAlloc: vsockBufAlloc,
			},
			payload: []byte{byte(window), byte(window), byte(window), byte(window)},
		}
		if !device.queuePending(packet) {
			t.Fatalf("window %d: queue packet", window)
		}

		head := uint16(window - 1)
		rxAddr := ramBase + testDataAddr + 0x20_000 + uint64(head)*0x100
		putDesc(memory, vsockQueueRx, head, rxAddr, vsockHdrLen+4, vringDescFWrite, 0)
		availPush(memory, vsockQueueRx, head)
		core.MMIOWrite(0x050, vsockQueueRx)
		if got := usedIndex(memory, vsockQueueRx); got != uint16(window-1) {
			t.Fatalf("window %d: packet crossed exhausted credit (used=%d)", window, got)
		}

		credit := vsockHdr{
			srcCID: device.guestCID, dstCID: vsockHostCID,
			srcPort: 1111, dstPort: 1025,
			typ: vsockTypeStream, op: vsockOpCreditUpdate,
			bufAlloc: 4, fwdCnt: 4 * window,
		}
		frame := make([]byte, vsockHdrLen)
		credit.marshalTo(frame)
		txAddr := ramBase + testDataAddr + 0x30_000 + uint64(head)*0x100
		if err := memory.writeAt(txAddr, frame); err != nil {
			t.Fatal(err)
		}
		putDesc(memory, vsockQueueTx, head, txAddr, uint32(len(frame)), 0, 0)
		availPush(memory, vsockQueueTx, head)
		core.MMIOWrite(0x050, vsockQueueTx)

		if got := usedIndex(memory, vsockQueueTx); got != uint16(window) {
			t.Fatalf("window %d: credit update not consumed (used=%d)", window, got)
		}
		if got := usedIndex(memory, vsockQueueRx); got != uint16(window) {
			t.Fatalf("window %d: restored credit did not flush packet (used=%d)", window, got)
		}
		if got := device.pending.Len(); got != 0 {
			t.Fatalf("window %d: %d packets remain pending", window, got)
		}
		if want := 4 * (window + 1); conn.txCnt != want {
			t.Fatalf("window %d: tx count = %d, want %d", window, conn.txCnt, want)
		}
		written := make([]byte, vsockHdrLen+4)
		if err := memory.readAt(rxAddr, written); err != nil {
			t.Fatal(err)
		}
		if hdr := parseVsockHdr(written); hdr.op != vsockOpRW || hdr.length != 4 {
			t.Fatalf("window %d: delivered header = %+v", window, hdr)
		}
		for _, value := range written[vsockHdrLen:] {
			if value != byte(window) {
				t.Fatalf("window %d: delivered payload = %v", window, written[vsockHdrLen:])
			}
		}
	}
}

func TestVsockTooSmallRXBufferNeverExposesTruncatedFrame(t *testing.T) {
	device := NewVsock(3, t.TempDir())
	memory := NewRAM(make([]byte, 2<<20), ramBase)
	irqs := &irqRec{raised: map[int]bool{}}
	core := NewCoreAt(device, memory, MMIOBaseArm64+MMIOStrideArm64, MMIOIRQArm64+1, irqs.line, "vsock-short-rx")
	setupQueue(memory, core, vsockQueueRx, 8)
	t.Cleanup(func() { _ = device.Close() })

	payload := []byte("complete")
	if !device.queuePending(vsockPkt{
		hdr: vsockHdr{
			srcCID: vsockHostCID, dstCID: device.guestCID,
			srcPort: 1025, dstPort: 1111,
			typ: vsockTypeStream, op: vsockOpRST,
		},
		payload: payload,
	}) {
		t.Fatal("queue packet")
	}

	shortAddr := uint64(ramBase + testDataAddr + 0x20_000)
	putDesc(memory, vsockQueueRx, 0, shortAddr, uint32(vsockHdrLen+len(payload)-1), vringDescFWrite, 0)
	availPush(memory, vsockQueueRx, 0)
	core.MMIOWrite(0x050, vsockQueueRx)
	if got := usedAt(memory, vsockQueueRx, 0).len; got != 0 {
		t.Fatalf("short descriptor reported %d valid bytes, want 0", got)
	}
	if got := device.pending.Len(); got != 1 {
		t.Fatalf("short descriptor consumed packet; pending = %d", got)
	}
	short := make([]byte, vsockHdrLen+len(payload)-1)
	if err := memory.readAt(shortAddr, short); err != nil {
		t.Fatal(err)
	}
	for index, value := range short {
		if value != 0 {
			t.Fatalf("short descriptor byte %d changed to %d", index, value)
		}
	}

	fullAddr := shortAddr + 0x100
	putDesc(memory, vsockQueueRx, 1, fullAddr, uint32(vsockHdrLen+len(payload)), vringDescFWrite, 0)
	availPush(memory, vsockQueueRx, 1)
	core.MMIOWrite(0x050, vsockQueueRx)
	used := usedAt(memory, vsockQueueRx, 1)
	if want := uint32(vsockHdrLen + len(payload)); used.len != want {
		t.Fatalf("full descriptor reported %d bytes, want %d", used.len, want)
	}
	if got := device.pending.Len(); got != 0 {
		t.Fatalf("full descriptor left %d packets pending", got)
	}
	frame := make([]byte, vsockHdrLen+len(payload))
	if err := memory.readAt(fullAddr, frame); err != nil {
		t.Fatal(err)
	}
	if got := string(frame[vsockHdrLen:]); got != string(payload) {
		t.Fatalf("payload = %q, want %q", got, payload)
	}
}

// Host->guest data must PARK on a full outbound FIFO, not RST the
// connection: a slow guest stalls the host producer (bounded memory: the
// pump's single read buffer) and draining the queue resumes delivery with
// no loss. RST-under-flood silently truncated multi-megabyte session-stdin
// transfers (observed delivering the guest-tools binary).
func TestVsockPumpHostBackpressureOnFullQueue(t *testing.T) {
	rig := newVsockNoRXRig(t)
	device := rig.device
	threshold := vsockMaxPending - vsockControlReserve
	// Fill the FIFO up to the data threshold with control packets.
	ctrl := vsockPkt{hdr: vsockHdr{op: vsockOpRST}}
	for device.pending.Len() < threshold {
		if !device.queuePending(ctrl) {
			t.Fatal("control queue filled before its fixed capacity")
		}
	}

	host, peer := net.Pipe()
	t.Cleanup(func() { _ = host.Close() })
	t.Cleanup(func() { _ = peer.Close() })
	key := connKey(1111, 1025)
	conn := &vsockConn{
		key: key, nc: host, established: true,
		outSig: make(chan struct{}, 1), done: make(chan struct{}),
	}
	device.conns[key] = conn
	go device.pumpHost(conn, 1111, 1025)

	if _, err := peer.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	// Parked: no queue growth, no RST, connection still open.
	deadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) {
		device.core.mu.Lock()
		n := device.pending.Len()
		closed := conn.closed
		device.core.mu.Unlock()
		if n != threshold {
			t.Fatalf("pending grew to %d past the data threshold while full", n)
		}
		if closed {
			t.Fatal("full queue RST-dropped a healthy connection")
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Free one slot: the parked pump wakes and queues the RW payload.
	device.core.mu.Lock()
	device.popPending()
	device.core.mu.Unlock()
	deadline = time.Now().Add(5 * time.Second)
	for {
		device.core.mu.Lock()
		pkt, _, ok := device.pending.Back()
		grown := device.pending.Len() == threshold
		closed := conn.closed
		device.core.mu.Unlock()
		if grown {
			if !ok || pkt.hdr.op != vsockOpRW || string(pkt.payload) != "hello" {
				t.Fatalf("resumed pump queued %+v, want RW hello", pkt.hdr)
			}
			if closed {
				t.Fatal("connection closed despite successful backpressure delivery")
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("parked pumpHost never resumed after the queue drained")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
