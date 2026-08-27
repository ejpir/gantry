package virtio

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
)

// virtio-net device (virtio device ID 1), backed by an AF_UNIX datagram
// packet endpoint. This is the same backend contract used by libkrun's
// krun_add_net_unixgram: datagrams contain raw Ethernet frames while the
// virtio-facing side prepends/removes struct virtio_net_hdr_v1.
const (
	virtioNetDeviceID = 1
	virtioNetFMac     = 5
	virtioNetHdrLen   = 12 // sizeof(struct virtio_net_hdr_v1)
	virtioNetRxQ      = 0
	virtioNetTxQ      = 1
	virtioNetMaxFrame = 65562
)

type packetConn interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
}

// PacketPolicy is the device's narrow egress-policy boundary.
type PacketPolicy interface {
	MatchTX(frame []byte) bool
	ObserveRX(frame []byte)
}

// TrafficObserver receives packet accounting at the device boundary.
type TrafficObserver interface {
	ObserveTX(frame []byte, allowed bool)
	ObserveRX(frame []byte)
}

type Net struct {
	core    *Core
	mac     [6]byte
	conn    packetConn
	policy  PacketPolicy
	traffic TrafficObserver

	localPath string
	pending   pendingRing[[]byte]
	started   sync.Once
	closeOnce sync.Once
	readDone  chan struct{}
	closeErr  error
	verbose   bool
}

// newUnixgramClientPath reserves a short, unique path and removes the
// placeholder before the socket is bound. macOS uses its short system-temp
// path to stay below the AF_UNIX limit. Windows keeps the client beside the
// supervisor-owned peer endpoint rather than depending on account TEMP.
func newUnixgramClientPath(endpoint string) (string, error) {
	dir := ""
	if runtime.GOOS == "windows" {
		dir = filepath.Dir(endpoint)
	}
	f, err := os.CreateTemp(dir, "gantry-net-*.sock")
	if err != nil {
		return "", err
	}
	path := f.Name()
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return "", err
	}
	if err := os.Remove(path); err != nil {
		return "", err
	}
	return path, nil
}

// NewNetUnixgram connects to a gvproxy/vmnet-helper Unix datagram endpoint.
// gvproxy's vfkit listener requires one VFKT registration datagram;
// vmnet-helper uses the same raw-frame transport without that handshake.
func NewNetUnixgram(endpoint string, mac [6]byte, vfkit bool) (*Net, error) {
	peer, err := net.ResolveUnixAddr("unixgram", endpoint)
	if err != nil {
		return nil, fmt.Errorf("resolve network endpoint: %w", err)
	}
	localPath, err := newUnixgramClientPath(endpoint)
	if err != nil {
		return nil, fmt.Errorf("create local network socket path: %w", err)
	}
	local, err := net.ResolveUnixAddr("unixgram", localPath)
	if err != nil {
		_ = os.Remove(localPath)
		return nil, fmt.Errorf("resolve local network socket: %w", err)
	}
	conn, err := net.DialUnix("unixgram", local, peer)
	if err != nil {
		_ = os.Remove(localPath)
		return nil, fmt.Errorf("connect network endpoint %s: %w", endpoint, err)
	}
	_ = conn.SetReadBuffer(7 << 20)
	_ = conn.SetWriteBuffer(7 << 20)
	if vfkit {
		if _, err := conn.Write([]byte("VFKT")); err != nil {
			_ = conn.Close()
			_ = os.Remove(localPath)
			return nil, fmt.Errorf("send VFKT handshake: %w", err)
		}
	}
	return &Net{
		mac:       mac,
		conn:      conn,
		localPath: localPath,
		verbose:   os.Getenv("GANTRY_DEBUG_NET") != "",
	}, nil
}

// qemuFrameConn adapts a stream connection to the frame-at-a-time
// packetConn interface using QEMU protocol framing (4-byte big-endian
// length + raw Ethernet frame). This is what gvisor-tap-vsock's
// AcceptQemu — and therefore our embedded netstack (internal/vnet) —
// expects on the other end. Policy and traffic observation live on Net so
// both this backend and external unixgram backends get identical accounting.
type qemuFrameConn struct {
	conn     net.Conn
	writeBuf []byte // reused by the single virtio TX queue
}

func (q *qemuFrameConn) Read(p []byte) (int, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(q.conn, hdr[:]); err != nil {
		return 0, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > virtioNetMaxFrame {
		return 0, fmt.Errorf("qemu frame %d bytes exceeds maximum %d", n, virtioNetMaxFrame)
	}
	if n > uint32(len(p)) {
		return 0, fmt.Errorf("qemu frame %d bytes > buffer %d", n, len(p))
	}
	return io.ReadFull(q.conn, p[:n])
}

func (q *qemuFrameConn) Write(p []byte) (int, error) {
	if len(p) > virtioNetMaxFrame {
		return 0, fmt.Errorf("qemu frame %d bytes exceeds maximum %d", len(p), virtioNetMaxFrame)
	}
	size := len(p) + 4
	if cap(q.writeBuf) < size {
		q.writeBuf = make([]byte, size)
	} else {
		q.writeBuf = q.writeBuf[:size]
	}
	binary.BigEndian.PutUint32(q.writeBuf[:4], uint32(len(p)))
	copy(q.writeBuf[4:], p)
	if err := writePacket(q.conn, q.writeBuf); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (q *qemuFrameConn) Close() error { return q.conn.Close() }

func writePacket(w io.Writer, packet []byte) error {
	for len(packet) != 0 {
		n, err := w.Write(packet)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		packet = packet[n:]
	}
	return nil
}

// NewNetConn attaches the device to a QEMU-framed stream endpoint —
// typically Stack.Dial() from the embedded netstack (no external gvproxy
// needed). The connection is unbuffered, so a busy guest TX serializes
// frame-by-frame against the netstack's read loop; fine at sandbox scale.
func NewNetConn(conn net.Conn, mac [6]byte) *Net {
	verbose := os.Getenv("GANTRY_DEBUG_NET") != ""
	return &Net{
		mac:     mac,
		conn:    &qemuFrameConn{conn: conn},
		verbose: verbose,
	}
}

// SetPolicy installs policy before the device starts processing queues.
func (v *Net) SetPolicy(policy PacketPolicy) { v.policy = policy }

// SetTrafficObserver installs accounting before queue processing starts.
func (v *Net) SetTrafficObserver(observer TrafficObserver) { v.traffic = observer }

func (v *Net) deviceID() uint32 { return virtioNetDeviceID }
func (v *Net) features() uint64 { return 1 << virtioNetFMac }
func (v *Net) numQueues() int   { return 2 }

func (v *Net) configRead(off uint64, p []byte) {
	// struct virtio_net_config starts with mac[6]. VIRTIO_NET_F_STATUS and
	// VIRTIO_NET_F_MQ are not offered, so the remaining fields are zero.
	var cfg [10]byte
	copy(cfg[:6], v.mac[:])
	if off < uint64(len(cfg)) {
		copy(p, cfg[off:])
	}
}
func (v *Net) configWrite(off uint64, p []byte) {}

func (v *Net) reset() {
	// Driver initialization starts with a reset. Keep the external packet
	// endpoint connected and discard only frames queued for the old rings.
	v.pending.Reset()
}

func (v *Net) start() {
	v.started.Do(func() {
		v.readDone = make(chan struct{})
		go func() {
			defer close(v.readDone)
			v.readLoop()
		}()
	})
}

func (v *Net) logf(format string, args ...any) {
	if v.verbose {
		fmt.Printf("[net] "+format+"\n", args...)
	}
}

func (v *Net) handleQueue(qn int) {
	switch qn {
	case virtioNetRxQ:
		v.tryRx()
	case virtioNetTxQ:
		v.handleTx()
	}
}

// writeFrame is the single egress enforcement and observation point shared by
// every packet backend.
func (v *Net) writeFrame(frame []byte) (int, error) {
	allowed := v.policy == nil || v.policy.MatchTX(frame)
	if v.traffic != nil {
		v.traffic.ObserveTX(frame, allowed)
	}
	if !allowed {
		v.logf("policy drop: frame %d bytes", len(frame))
		return len(frame), nil // silently dropped, like any ethernet drop
	}
	n, err := v.conn.Write(frame)
	if err == nil {
		v.logf("tx frame %d bytes", len(frame))
	}
	return n, err
}

// readFrame observes ingress before it reaches the guest receive queue.
func (v *Net) readFrame(frame []byte) (int, error) {
	n, err := v.conn.Read(frame)
	if n > 0 {
		if v.policy != nil {
			v.policy.ObserveRX(frame[:n])
		}
		if v.traffic != nil {
			v.traffic.ObserveRX(frame[:n])
		}
	}
	return n, err
}

// handleTx removes the 12-byte virtio header and sends one raw Ethernet frame
// per Unix datagram. No checksum/GSO features are advertised, so Linux emits
// complete packets and the header is metadata-only.
func (v *Net) handleTx() {
	q := &v.core.queues[virtioNetTxQ]
	for {
		head, chain, ok := v.core.availChain(virtioNetTxQ)
		if !ok {
			return
		}
		out, _ := splitChain(chain)
		buf, err := v.core.readChains(out)
		if err == nil && len(buf) >= virtioNetHdrLen {
			frame := buf[virtioNetHdrLen:]
			if len(frame) > 0 {
				if _, err := v.writeFrame(frame); err != nil {
					// Ethernet may drop packets. Always return the descriptor so a
					// full host socket cannot wedge the guest TX queue forever.
					v.logf("drop tx frame (%d bytes): %v", len(frame), err)
				}
			}
		} else if err != nil {
			v.logf("read tx descriptors: %v", err)
		}
		v.core.pushUsed(q, head, 0)
	}
}

// readLoop receives complete raw Ethernet frames from the packet provider.
func (v *Net) readLoop() {
	buf := make([]byte, virtioNetMaxFrame)
	for {
		n, err := v.readFrame(buf)
		if n > 0 {
			v.core.mu.Lock()
			if v.enqueueRXFrame(buf[:n]) {
				v.logf("rx frame %d bytes", n)
				v.tryRx()
			} else {
				v.logf("drop rx frame: no guest buffers")
			}
			v.core.mu.Unlock()
		}
		if err != nil {
			// Any read error from the unixgram backend is terminal (the
			// gvproxy socket going away can't be retried); net.Error.
			// Temporary() is deprecated and never true for packet conns.
			v.logf("packet backend stopped: %v", err)
			return
		}
	}
}

// enqueueRXFrame copies frame into the bounded guest-facing queue. The caller
// holds core.mu, so checking capacity before allocating is atomic with the
// enqueue: a guest withholding RX descriptors makes every drop allocation
// free.
func (v *Net) enqueueRXFrame(frame []byte) bool {
	if v.pending.Full() {
		return false
	}
	packet := make([]byte, virtioNetHdrLen+len(frame))
	copy(packet[virtioNetHdrLen:], frame)
	_, ok := v.pending.Push(packet)
	return ok
}

// tryRx prepends a zeroed virtio_net_hdr_v1 and scatters each frame into one
// guest-provided receive descriptor chain. Called with core.mu held.
func (v *Net) tryRx() {
	q := &v.core.queues[virtioNetRxQ]
	if !q.ready {
		return
	}
	for v.pending.Len() != 0 {
		head, chain, ok := v.core.availChain(virtioNetRxQ)
		if !ok {
			return
		}
		_, in := splitChain(chain)
		packet, _, _ := v.pending.Front()

		capacity := uint32(0)
		for _, d := range in {
			capacity += d.len
		}
		if capacity < uint32(len(*packet)) {
			v.logf("rx descriptor too small: %d < %d", capacity, len(*packet))
			v.core.pushUsed(q, head, 0)
			v.pending.Pop()
			continue
		}
		n, err := v.core.writeChains(in, *packet)
		if err != nil {
			v.logf("write rx descriptors: %v", err)
			n = 0
		}
		v.core.pushUsed(q, head, n)
		v.pending.Pop()
	}
}

// netMaxChainBytes caps one TX/RX chain at the largest legitimate frame
// plus the 12-byte virtio_net_hdr_v1 (no GSO features are offered, so
// frames are complete packets). A guest declaring more is fishing for a
// guest-RAM-sized host allocation (review finding 2).
const netMaxChainBytes = virtioNetMaxFrame + virtioNetHdrLen + 1024

func (v *Net) maxChainBytes(qn int) uint64 { return netMaxChainBytes }

// Close shuts the packet endpoint and removes the unixgram client
// socket (VM teardown; see Machine.Close).
func (v *Net) Close() error {
	v.closeOnce.Do(func() {
		if v.conn != nil {
			v.closeErr = v.conn.Close()
		}
		if v.readDone != nil {
			<-v.readDone
		}
		if v.localPath != "" {
			if err := os.Remove(v.localPath); v.closeErr == nil && err != nil && !os.IsNotExist(err) {
				v.closeErr = err
			}
		}
	})
	return v.closeErr
}

func (v *Net) setCore(c *Core) { v.core = c }
