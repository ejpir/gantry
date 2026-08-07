package virtio

import (
	"encoding/binary"
	"fmt"
	"github.com/ejpir/gantry/internal/gutil"
	"net"
	"os"
	"path/filepath"
	"time"
)

// virtio-vsock (device ID 19): stream sockets between guest and host.
//
// vminitd in the nerdbox rootfs *dials back* to the host (CID 2) on ports
// 1025/1026 to speak ttrpc. We forward each such connection to a host unix
// socket at <forwardDir>/<port> — same role as the reference uds_forward — so a
// host-side ttrpc server can answer (or netcat for experiments).
const (
	VsockDeviceID = 19

	vsockHostCID = 2

	vsockOpRequest      = 1
	vsockOpResponse     = 2
	vsockOpRST          = 3
	vsockOpShutdown     = 4
	vsockOpRW           = 5
	vsockOpCreditUpdate = 6
	vsockOpCreditReq    = 7

	vsockTypeStream = 1

	vsockHdrLen   = 44
	vsockBufAlloc = 65536
	vsockQueueRx  = 0
	vsockQueueTx  = 1
	vsockQueueEv  = 2
)

type vsockHdr struct {
	srcCID, dstCID   uint64
	srcPort, dstPort uint32
	length           uint32
	typ, op          uint16
	flags            uint32
	bufAlloc, fwdCnt uint32
}

func parseVsockHdr(b []byte) vsockHdr {
	return vsockHdr{
		srcCID:   binary.LittleEndian.Uint64(b[0:]),
		dstCID:   binary.LittleEndian.Uint64(b[8:]),
		srcPort:  binary.LittleEndian.Uint32(b[16:]),
		dstPort:  binary.LittleEndian.Uint32(b[20:]),
		length:   binary.LittleEndian.Uint32(b[24:]),
		typ:      binary.LittleEndian.Uint16(b[28:]),
		op:       binary.LittleEndian.Uint16(b[30:]),
		flags:    binary.LittleEndian.Uint32(b[32:]),
		bufAlloc: binary.LittleEndian.Uint32(b[36:]),
		fwdCnt:   binary.LittleEndian.Uint32(b[40:]),
	}
}

func (h vsockHdr) marshal() []byte {
	b := make([]byte, vsockHdrLen)
	binary.LittleEndian.PutUint64(b[0:], h.srcCID)
	binary.LittleEndian.PutUint64(b[8:], h.dstCID)
	binary.LittleEndian.PutUint32(b[16:], h.srcPort)
	binary.LittleEndian.PutUint32(b[20:], h.dstPort)
	binary.LittleEndian.PutUint32(b[24:], h.length)
	binary.LittleEndian.PutUint16(b[28:], h.typ)
	binary.LittleEndian.PutUint16(b[30:], h.op)
	binary.LittleEndian.PutUint32(b[32:], h.flags)
	binary.LittleEndian.PutUint32(b[36:], h.bufAlloc)
	binary.LittleEndian.PutUint32(b[40:], h.fwdCnt)
	return b
}

type vsockPkt struct {
	hdr     vsockHdr
	payload []byte
}

type vsockConn struct {
	key          uint64
	nc           net.Conn
	peerBufAlloc uint32 // guest's receive buffer size
	peerFwdCnt   uint32 // bytes guest has consumed
	txCnt        uint32 // payload bytes we sent to guest
	rxCnt        uint32 // payload bytes we consumed from guest (our fwd_cnt)
	guestTx      uint32 // payload bytes the guest sent us (credit accounting)
	outQBytes    int    // payload bytes currently sitting in outQ
	closed       bool
	established  bool          // host-originated conns wait for the guest's RESPONSE
	outQ         [][]byte      // guest->host payloads awaiting socket write
	outSig       chan struct{} // 1-cap; signals pumpOut
	done         chan struct{} // closed on conn teardown; stops pumpOut
}

func connKey(srcPort, dstPort uint32) uint64 { return uint64(srcPort)<<32 | uint64(dstPort) }

type Vsock struct {
	guestCID     uint64
	forwardDir   string
	dial         func(port uint32) (net.Conn, error)
	conns        map[uint64]*vsockConn
	pending      []vsockPkt     // outbound FIFO (control + data)
	listeners    []net.Listener // AddListen sockets (closed at VM teardown)
	core         *Core
	verboseLog   bool
	nextHostPort uint32
}

func NewVsock(guestCID uint64, forwardDir string) *Vsock {
	_ = os.MkdirAll(forwardDir, 0o755)
	return &Vsock{
		guestCID:     guestCID,
		forwardDir:   forwardDir,
		conns:        map[uint64]*vsockConn{},
		nextHostPort: 0x100000,
		verboseLog:   gutil.EnvOr("GANTRY_DEBUG_VSOCK", "MINIVM_DEBUG_VSOCK") != "",
		dial: func(port uint32) (net.Conn, error) {
			path := filepath.Join(forwardDir, fmt.Sprintf("%d.sock", port))
			return net.DialTimeout("unix", path, 3*time.Second)
		},
	}
}

// AddListen makes the device accept HOST-originated connections: a client
// connecting to <forwardDir>/listen-<guestPort>.sock triggers a vsock
// REQUEST from host CID 2 to the guest's listening port (e.g. vminitd's
// streaming service on 1026). Mirrors the reference VMM's vsock listen-port registration.
func (v *Vsock) AddListen(guestPort uint32) (string, error) {
	path := filepath.Join(v.forwardDir, fmt.Sprintf("listen-%d.sock", guestPort))
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return "", err
	}
	v.listeners = append(v.listeners, ln)
	fmt.Printf("[vsock] host->guest listen port %d at %s\n", guestPort, path)
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			v.core.mu.Lock()
			srcPort := v.nextHostPort
			v.nextHostPort++
			key := connKey(guestPort, srcPort)
			c := &vsockConn{key: key, nc: nc, peerBufAlloc: vsockBufAlloc, outSig: make(chan struct{}, 1), done: make(chan struct{})}
			v.conns[key] = c
			go v.pumpOut(c)
			v.pending = append(v.pending, vsockPkt{hdr: vsockHdr{
				srcCID: vsockHostCID, dstCID: v.guestCID,
				srcPort: srcPort, dstPort: guestPort,
				typ: vsockTypeStream, op: vsockOpRequest,
				bufAlloc: vsockBufAlloc,
			}})
			v.tryFlush()
			v.core.mu.Unlock()
			v.logf("host-originated conn to guest port %d (srcPort %d)", guestPort, srcPort)
		}
	}()
	return path, nil
}

func (v *Vsock) deviceID() uint32 { return VsockDeviceID }
func (v *Vsock) features() uint64 { return 0 }
func (v *Vsock) numQueues() int   { return 3 }
func (v *Vsock) reset() {
	for k, c := range v.conns {
		c.closed = true
		_ = c.nc.Close()
		close(c.done) // wake pumpOut so it doesn't leak on the socket
		delete(v.conns, k)
	}
	v.pending = nil
}

func (v *Vsock) configRead(off uint64, p []byte) {
	var cfg [8]byte
	binary.LittleEndian.PutUint64(cfg[:], v.guestCID)
	if off < 8 {
		copy(p, cfg[off:])
	}
}
func (v *Vsock) configWrite(off uint64, p []byte) {}

func (v *Vsock) logf(format string, a ...any) {
	if v.verboseLog {
		fmt.Printf("[vsock] "+format+"\n", a...)
	}
}

// ---------------- guest -> host (tx queue) -----------------------------------

func (v *Vsock) handleQueue(qn int) {
	switch qn {
	case vsockQueueTx:
		v.handleTx()
	case vsockQueueRx:
		v.tryFlush()
	case vsockQueueEv:
		// Event queue: the driver posts buffers for FUTURE events
		// (TRANSPORT_RESET etc.). Hold them — do NOT return them unused.
		// Returning them raises a used-buffer interrupt, which makes the
		// driver's eventq worker repost+notify, which we would answer with
		// another used+IRQ — a ping-pong that storms the guest with tens
		// of thousands of interrupts per second and burns a host core.
		// (We never deliver events; if that changes, consume buffers here.)
	}
}

func (v *Vsock) handleTx() {
	q := &v.core.queues[vsockQueueTx]
	for {
		head, chain, ok := v.core.availChain(vsockQueueTx)
		if !ok {
			return
		}
		out, _ := splitChain(chain)
		data, err := v.core.readChains(out)
		if err != nil || len(data) < vsockHdrLen {
			v.core.pushUsed(q, head, 0)
			continue
		}
		hdr := parseVsockHdr(data[:vsockHdrLen])
		payload := data[vsockHdrLen:]
		v.logf("tx op=%d %d:%d -> %d:%d len=%d flags=%#x", hdr.op, hdr.srcCID, hdr.srcPort, hdr.dstCID, hdr.dstPort, hdr.length, hdr.flags)
		v.core.pushUsed(q, head, 0) // tx buffers are consumed, not filled

		if hdr.typ != vsockTypeStream {
			continue
		}
		key := connKey(hdr.srcPort, hdr.dstPort)
		c := v.conns[key]

		switch hdr.op {
		case vsockOpRequest:
			v.logf("REQUEST %d:%d -> %d:%d", hdr.srcCID, hdr.srcPort, hdr.dstCID, hdr.dstPort)
			if hdr.dstCID != vsockHostCID || c != nil {
				v.enqueueCtrl(hdr, vsockOpRST, 0)
				break
			}
			nc, err := v.dial(hdr.dstPort)
			if err != nil {
				v.logf("dial host port %d failed: %v -> RST", hdr.dstPort, err)
				v.enqueueCtrl(hdr, vsockOpRST, 0)
				break
			}
			c = &vsockConn{key: key, nc: nc, peerBufAlloc: hdr.bufAlloc, peerFwdCnt: hdr.fwdCnt, established: true, outSig: make(chan struct{}, 1), done: make(chan struct{})}
			v.conns[key] = c
			v.enqueueCtrl(hdr, vsockOpResponse, 0)
			go v.pumpHost(c, hdr.srcPort, hdr.dstPort)
			go v.pumpOut(c)
			v.logf("connected -> forwarded to host port %d", hdr.dstPort)

		case vsockOpRW:
			if c == nil || c.closed {
				v.enqueueCtrl(hdr, vsockOpRST, 0)
				break
			}
			c.peerBufAlloc, c.peerFwdCnt = hdr.bufAlloc, hdr.fwdCnt
			if len(payload) > 0 {
				// Never write to the host socket here: handleTx runs under
				// core.mu, and a blocking write (peer not draining) wedges
				// the whole device — the next RPC is never delivered.
				// Queue it; pumpOut writes + accounts credit off-lock.
				//
				// Enforce the receive credit we advertise: the guest may
				// have at most vsockBufAlloc bytes in flight beyond what
				// pumpOut consumed. A hostile guest that ignores credit
				// would grow outQ without bound while a stalled host
				// consumer holds pumpOut — RST the connection, and bound
				// the queue in bytes AND packets regardless of the
				// accounting (belt and braces, like maxExitTrailerHold).
				c.guestTx += uint32(len(payload))
				if c.guestTx-c.rxCnt > vsockBufAlloc ||
					c.outQBytes+len(payload) > vsockBufAlloc ||
					len(c.outQ) >= vsockOutQMaxPackets {
					v.logf("RW beyond credit/queue bounds (guestTx=%d rxCnt=%d q=%d pkts/%dB) -> RST",
						c.guestTx, c.rxCnt, len(c.outQ), c.outQBytes)
					v.closeConn(c, hdr, true)
					break
				}
				c.outQ = append(c.outQ, append([]byte(nil), payload...))
				c.outQBytes += len(payload)
				select {
				case c.outSig <- struct{}{}:
				default:
				}
			}

		case vsockOpResponse:
			// answer to a host-originated REQUEST: connection established
			if c != nil && !c.established {
				c.established = true
				c.peerBufAlloc, c.peerFwdCnt = hdr.bufAlloc, hdr.fwdCnt
				go v.pumpHost(c, hdr.srcPort, hdr.dstPort)
				v.logf("guest accepted host-originated conn (ports %d<->%d)", hdr.srcPort, hdr.dstPort)
			}

		case vsockOpCreditReq:
			if c != nil {
				c.peerBufAlloc, c.peerFwdCnt = hdr.bufAlloc, hdr.fwdCnt
				v.enqueueCtrl(hdr, vsockOpCreditUpdate, 0)
			}

		case vsockOpShutdown, vsockOpRST:
			if c != nil {
				v.closeConn(c, hdr, hdr.op == vsockOpShutdown)
			}
		}
	}
}

// pumpOut drains c.outQ to the host socket. Socket writes happen OFF the
// device lock: a peer that stops draining must not wedge the vsock device
// (a blocking write under core.mu deadlocks every channel — observed as
// the second exec's Create RPC never reaching vminitd).
func (v *Vsock) pumpOut(c *vsockConn) {
	trigger := vsockHdr{srcPort: uint32(c.key >> 32), dstPort: uint32(c.key)}
	for {
		v.core.mu.Lock()
		if len(c.outQ) == 0 {
			v.core.mu.Unlock()
			select {
			case <-c.done: // conn torn down (closeConn/reset)
				return
			case <-c.outSig:
			}
			continue
		}
		payload := c.outQ[0]
		c.outQ = c.outQ[1:]
		c.outQBytes -= len(payload)
		v.core.mu.Unlock()

		if _, err := c.nc.Write(payload); err != nil {
			v.core.mu.Lock()
			if !c.closed {
				v.logf("pumpOut: host socket write: %v -> RST", err)
				v.closeConn(c, trigger, true)
			}
			v.core.mu.Unlock()
			return
		}

		v.core.mu.Lock()
		if !c.closed {
			c.rxCnt += uint32(len(payload))
			v.enqueueCtrl(trigger, vsockOpCreditUpdate, 0)
		}
		v.core.mu.Unlock()
	}
}

// enqueueCtrl queues a control packet (RESPONSE/RST/CREDIT_UPDATE) back to
// the guest, addressing it to the peer of the packet that triggered it.
func (v *Vsock) enqueueCtrl(trigger vsockHdr, op uint16, flags uint32) {
	v.pending = append(v.pending, vsockPkt{hdr: vsockHdr{
		srcCID:   vsockHostCID,
		dstCID:   v.guestCID,
		srcPort:  trigger.dstPort,
		dstPort:  trigger.srcPort,
		typ:      vsockTypeStream,
		op:       op,
		flags:    flags,
		bufAlloc: vsockBufAlloc,
		fwdCnt:   v.rxCntFor(trigger),
	}})
	v.tryFlush()
}

func (v *Vsock) rxCntFor(trigger vsockHdr) uint32 {
	if c := v.conns[connKey(trigger.srcPort, trigger.dstPort)]; c != nil {
		return c.rxCnt
	}
	return 0
}

func (v *Vsock) closeConn(c *vsockConn, trigger vsockHdr, sendRST bool) {
	if c.closed {
		return
	}
	c.closed = true
	_ = c.nc.Close()
	close(c.done) // release pumpOut; sending on outSig after this is a no-op
	delete(v.conns, c.key)
	if sendRST {
		v.logf("closeConn: sending RST (op trigger=%d ports %d->%d)", trigger.op, trigger.srcPort, trigger.dstPort)
		v.enqueueCtrl(trigger, vsockOpRST, 0)
	}
}

// ---------------- host -> guest (rx queue) -----------------------------------

// vsockMaxPending caps the outbound FIFO (same bound as virtio-net).
// tryFlush can stall indefinitely when the guest stops posting rx
// buffers or granting credit; without a cap a stuck or hostile guest
// grows host memory without limit just by holding a stream open.
const vsockMaxPending = virtioNetMaxQueue

// vsockOutQMaxPackets caps the per-connection guest->host queue in
// PACKETS (the byte side is bounded by vsockBufAlloc credit): without
// it, a guest sending 1-byte RW frames within credit still forces one
// slice allocation per packet without limit against a stalled consumer.
const vsockOutQMaxPackets = 1024

// pumpHost reads from the host unix socket and forwards to the guest.
func (v *Vsock) pumpHost(c *vsockConn, srcPort, dstPort uint32) {
	buf := make([]byte, 32*1024)
	for {
		n, err := c.nc.Read(buf)
		if n > 0 {
			v.logf("host->guest %d bytes", n)
			payload := append([]byte(nil), buf[:n]...)
			v.core.mu.Lock()
			if len(v.pending) >= vsockMaxPending {
				// queue full: drop the connection with RST rather than
				// buffer without bound for a non-draining guest.
				v.logf("pumpHost: %d pending -> RST", len(v.pending))
				v.closeConn(c, vsockHdr{op: vsockOpRW, srcPort: srcPort, dstPort: dstPort}, true)
				v.tryFlush()
				v.core.mu.Unlock()
				return
			}
			v.pending = append(v.pending, vsockPkt{
				hdr: vsockHdr{
					srcCID: vsockHostCID, dstCID: v.guestCID,
					srcPort: dstPort, dstPort: srcPort,
					typ: vsockTypeStream, op: vsockOpRW,
					bufAlloc: vsockBufAlloc, fwdCnt: c.rxCnt,
				},
				payload: payload,
			})
			v.tryFlush()
			v.core.mu.Unlock()
		}
		if err != nil {
			v.core.mu.Lock()
			if !c.closed {
				v.logf("pumpHost: host socket read: %v -> RST", err)
				c.closed = true
				close(c.done)
				delete(v.conns, c.key)
				v.pending = append(v.pending, vsockPkt{hdr: vsockHdr{
					srcCID: vsockHostCID, dstCID: v.guestCID,
					srcPort: dstPort, dstPort: srcPort,
					typ: vsockTypeStream, op: vsockOpRST,
					bufAlloc: vsockBufAlloc, fwdCnt: c.rxCnt,
				}})
				v.tryFlush()
			}
			v.core.mu.Unlock()
			return
		}
	}
}

// tryFlush moves pending outbound packets into guest-posted rx buffers.
// Called with core.mu held.
func (v *Vsock) tryFlush() {
	if v.core == nil {
		return
	}
	q := &v.core.queues[vsockQueueRx]
	for len(v.pending) > 0 {
		pkt := v.pending[0]
		// credit check for data packets
		if pkt.hdr.op == vsockOpRW && len(pkt.payload) > 0 {
			c := v.conns[connKey(pkt.hdr.dstPort, pkt.hdr.srcPort)]
			if c != nil {
				credit := int64(c.peerBufAlloc) - int64(c.peerFwdCnt) - int64(c.txCnt)
				if credit < int64(len(pkt.payload)) {
					v.logf("tryFlush: stalled on credit (%d < %d)", credit, len(pkt.payload))
					return // wait for the guest to consume
				}
			}
		}
		head, chain, ok := v.core.availChain(vsockQueueRx)
		if !ok {
			v.logf("tryFlush: %d pending, no rx buffers", len(v.pending))
			return // no rx buffers posted yet
		}
		v.logf("tryFlush: delivering op=%d len=%d", pkt.hdr.op, len(pkt.payload))
		_, in := splitChain(chain)
		if len(in) == 0 {
			// a chain with no guest-writable descriptor can never carry a
			// frame; return the descriptor and drop the packet rather than
			// spinning on it forever.
			v.core.pushUsed(q, head, 0)
			v.pending = v.pending[1:]
			continue
		}
		hdr := pkt.hdr
		hdr.length = uint32(len(pkt.payload))
		// the vsock frame (header + payload) must be written CONTIGUOUSLY
		// across the chain's descriptors: writing the header into desc[0]
		// and the payload from desc[1] is only valid when desc[0] is
		// exactly 44 bytes — guests post large descs, which corrupted
		// frames (guest ttrpc server then RST the connection).
		frame := append(hdr.marshal(), pkt.payload...)
		total, err := v.core.writeChains(in, frame)
		if err != nil || total < vsockHdrLen {
			v.logf("tryFlush: write failed (%v, %d)", err, total)
			// return the rx descriptor to the guest (otherwise it leaks)
			// and drop the packet; the peer's next send resets the conn.
			v.core.pushUsed(q, head, total)
			v.pending = v.pending[1:]
			continue
		}
		if c := v.conns[connKey(pkt.hdr.dstPort, pkt.hdr.srcPort)]; c != nil && total > vsockHdrLen {
			c.txCnt += total - vsockHdrLen
		}
		v.core.pushUsed(q, head, total)
		v.pending = v.pending[1:]
	}
}

// vsockMaxChainBytes caps one packet chain at the 44-byte header plus
// the receive buffer credit we grant peers (vsockBufAlloc) plus slack.
// A guest declaring more is fishing for a guest-RAM-sized host
// allocation (review finding 2).
const vsockMaxChainBytes = vsockBufAlloc + vsockHdrLen + 1024

func (v *Vsock) maxChainBytes(qn int) uint64 { return vsockMaxChainBytes }

// Close tears down the host-originated listeners and every forwarded
// connection (VM teardown; see Machine.Close). Connection teardown
// mirrors reset(): closed-flag first so pumpOut/closeConn can't
// double-close c.done.
func (v *Vsock) Close() error {
	for _, l := range v.listeners {
		_ = l.Close()
	}
	if v.core == nil {
		return nil
	}
	v.core.mu.Lock()
	for k, c := range v.conns {
		c.closed = true
		_ = c.nc.Close()
		close(c.done)
		delete(v.conns, k)
	}
	v.core.mu.Unlock()
	return nil
}

func (v *Vsock) setCore(c *Core) { v.core = c }
