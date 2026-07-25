package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"
)

// virtio-vsock (device ID 19): stream sockets between guest and host.
//
// vminitd in the nerdbox rootfs *dials back* to the host (CID 2) on ports
// 1025/1026 to speak ttrpc. We forward each such connection to a host unix
// socket at <forwardDir>/<port> — same role as sailor's uds_forward — so a
// host-side ttrpc server can answer (or netcat for experiments).
const (
	virtioVsockDeviceID = 19

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
	closed       bool
	established  bool          // host-originated conns wait for the guest's RESPONSE
	outQ         [][]byte      // guest->host payloads awaiting socket write
	outSig       chan struct{} // 1-cap; signals pumpOut
	done         chan struct{} // closed on conn teardown; stops pumpOut
}

func connKey(srcPort, dstPort uint32) uint64 { return uint64(srcPort)<<32 | uint64(dstPort) }

type virtioVsock struct {
	guestCID     uint64
	forwardDir   string
	dial         func(port uint32) (net.Conn, error)
	conns        map[uint64]*vsockConn
	pending      []vsockPkt // outbound FIFO (control + data)
	core         *virtioMMIOCore
	verboseLog   bool
	nextHostPort uint32
}

func newVirtioVsock(guestCID uint64, forwardDir string) *virtioVsock {
	os.MkdirAll(forwardDir, 0o755)
	return &virtioVsock{
		guestCID:     guestCID,
		forwardDir:   forwardDir,
		conns:        map[uint64]*vsockConn{},
		nextHostPort: 0x100000,
		verboseLog:   envOr("GANTRY_DEBUG_VSOCK", "MINIVM_DEBUG_VSOCK") != "",
		dial: func(port uint32) (net.Conn, error) {
			path := filepath.Join(forwardDir, fmt.Sprintf("%d.sock", port))
			return net.DialTimeout("unix", path, 3*time.Second)
		},
	}
}

// AddListen makes the device accept HOST-originated connections: a client
// connecting to <forwardDir>/listen-<guestPort>.sock triggers a vsock
// REQUEST from host CID 2 to the guest's listening port (e.g. vminitd's
// streaming service on 1026). Mirrors sailor_config_add_vsock_port_listen.
func (v *virtioVsock) AddListen(guestPort uint32) (string, error) {
	path := filepath.Join(v.forwardDir, fmt.Sprintf("listen-%d.sock", guestPort))
	os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return "", err
	}
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

func (v *virtioVsock) deviceID() uint32 { return virtioVsockDeviceID }
func (v *virtioVsock) features() uint64 { return 0 }
func (v *virtioVsock) numQueues() int   { return 3 }
func (v *virtioVsock) reset() {
	for k, c := range v.conns {
		c.closed = true
		c.nc.Close()
		close(c.done) // wake pumpOut so it doesn't leak on the socket
		delete(v.conns, k)
	}
	v.pending = nil
}

func (v *virtioVsock) configRead(off uint64, p []byte) {
	var cfg [8]byte
	binary.LittleEndian.PutUint64(cfg[:], v.guestCID)
	if off < 8 {
		copy(p, cfg[off:])
	}
}
func (v *virtioVsock) configWrite(off uint64, p []byte) {}

func (v *virtioVsock) logf(format string, a ...any) {
	if v.verboseLog {
		fmt.Printf("[vsock] "+format+"\n", a...)
	}
}

// ---------------- guest -> host (tx queue) -----------------------------------

func (v *virtioVsock) handleQueue(qn int) {
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

func (v *virtioVsock) handleTx() {
	q := &v.core.queues[vsockQueueTx]
	for {
		head, chain, ok := v.core.availChain(q)
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
				c.outQ = append(c.outQ, append([]byte(nil), payload...))
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
func (v *virtioVsock) pumpOut(c *vsockConn) {
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
func (v *virtioVsock) enqueueCtrl(trigger vsockHdr, op uint16, flags uint32) {
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

func (v *virtioVsock) rxCntFor(trigger vsockHdr) uint32 {
	if c := v.conns[connKey(trigger.srcPort, trigger.dstPort)]; c != nil {
		return c.rxCnt
	}
	return 0
}

func (v *virtioVsock) closeConn(c *vsockConn, trigger vsockHdr, sendRST bool) {
	if c.closed {
		return
	}
	c.closed = true
	c.nc.Close()
	close(c.done) // release pumpOut; sending on outSig after this is a no-op
	delete(v.conns, c.key)
	if sendRST {
		v.logf("closeConn: sending RST (op trigger=%d ports %d->%d)", trigger.op, trigger.srcPort, trigger.dstPort)
		v.enqueueCtrl(trigger, vsockOpRST, 0)
	}
}

// ---------------- host -> guest (rx queue) -----------------------------------

// pumpHost reads from the host unix socket and forwards to the guest.
func (v *virtioVsock) pumpHost(c *vsockConn, srcPort, dstPort uint32) {
	buf := make([]byte, 32*1024)
	for {
		n, err := c.nc.Read(buf)
		if n > 0 {
			v.logf("host->guest %d bytes", n)
			payload := append([]byte(nil), buf[:n]...)
			v.core.mu.Lock()
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
func (v *virtioVsock) tryFlush() {
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
		head, chain, ok := v.core.availChain(q)
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
