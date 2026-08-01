package virtio

import (
	"encoding/binary"
	"fmt"
	"gantry/internal/gutil"
	"gantry/internal/netpol"
	"io"
	"net"
	"os"
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
	virtioNetMaxQueue = 256
)

type packetConn interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
}

type Net struct {
	core *Core
	mac  [6]byte
	conn packetConn

	localPath string
	pending   [][]byte
	started   sync.Once
	verbose   bool
}

// newUnixgramClientPath reserves a short, unique path and removes the
// placeholder before the socket is bound. Keeping it under the system temp
// directory avoids exceeding macOS's shorter AF_UNIX path limit when the peer
// endpoint is nested under a long temporary directory.
func newUnixgramClientPath() (string, error) {
	f, err := os.CreateTemp("", "gantry-net-*.sock")
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
	localPath, err := newUnixgramClientPath()
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
			conn.Close()
			_ = os.Remove(localPath)
			return nil, fmt.Errorf("send VFKT handshake: %w", err)
		}
	}
	return &Net{
		mac:       mac,
		conn:      conn,
		localPath: localPath,
		verbose:   gutil.EnvOr("GANTRY_DEBUG_NET", "MINIVM_DEBUG_NET") != "",
	}, nil
}

// qemuFrameConn adapts a stream connection to the frame-at-a-time
// packetConn interface using QEMU protocol framing (4-byte big-endian
// length + raw Ethernet frame). This is what gvisor-tap-vsock's
// AcceptQemu — and therefore our embedded netstack (internal/vnet) —
// expects on the other end. A netpol.Policy hooks every frame here: TX is
// filtered (guest can't bypass it — we are the wire), RX is snooped for
// DNS answers that feed the policy's dynamic allow table.
type qemuFrameConn struct {
	conn    net.Conn
	pol     *netpol.Policy
	verbose bool
}

func (q qemuFrameConn) Read(p []byte) (int, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(q.conn, hdr[:]); err != nil {
		return 0, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > uint32(len(p)) {
		return 0, fmt.Errorf("qemu frame %d bytes > buffer %d", n, len(p))
	}
	m, err := io.ReadFull(q.conn, p[:n])
	if err == nil && q.pol != nil {
		q.pol.ObserveRX(p[:m])
	}
	return m, err
}

func (q qemuFrameConn) Write(p []byte) (int, error) {
	if q.pol != nil && !q.pol.MatchTX(p) {
		if q.verbose {
			fmt.Printf("[net] policy drop: %s\n", netpol.Summarize(p))
		}
		return len(p), nil // silently dropped, like any ethernet drop
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(p)))
	buf := append(hdr[:], p...)
	if _, err := q.conn.Write(buf); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (q qemuFrameConn) Close() error { return q.conn.Close() }

// NewNetConn attaches the device to a QEMU-framed stream endpoint —
// typically Stack.Dial() from the embedded netstack (no external gvproxy
// needed). The connection is unbuffered, so a busy guest TX serializes
// frame-by-frame against the netstack's read loop; fine at sandbox scale.
func NewNetConn(conn net.Conn, mac [6]byte) *Net {
	return NewNetConnPolicy(conn, mac, nil)
}

// NewNetConnPolicy is NewNetConn with an egress network policy enforced on
// the link (see internal/netpol).
func NewNetConnPolicy(conn net.Conn, mac [6]byte, pol *netpol.Policy) *Net {
	verbose := gutil.EnvOr("GANTRY_DEBUG_NET", "MINIVM_DEBUG_NET") != ""
	return &Net{
		mac:     mac,
		conn:    qemuFrameConn{conn: conn, pol: pol, verbose: verbose},
		verbose: verbose,
	}
}

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
	v.pending = nil
}

func (v *Net) start() {
	v.started.Do(func() { go v.readLoop() })
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
				if _, err := v.conn.Write(frame); err != nil {
					// Ethernet may drop packets. Always return the descriptor so a
					// full host socket cannot wedge the guest TX queue forever.
					v.logf("drop tx frame (%d bytes): %v", len(frame), err)
				} else {
					v.logf("tx frame %d bytes", len(frame))
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
		n, err := v.conn.Read(buf)
		if n > 0 {
			frame := append([]byte(nil), buf[:n]...)
			v.core.mu.Lock()
			if len(v.pending) < virtioNetMaxQueue {
				v.pending = append(v.pending, frame)
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

// tryRx prepends a zeroed virtio_net_hdr_v1 and scatters each frame into one
// guest-provided receive descriptor chain. Called with core.mu held.
func (v *Net) tryRx() {
	q := &v.core.queues[virtioNetRxQ]
	if !q.ready {
		return
	}
	for len(v.pending) > 0 {
		head, chain, ok := v.core.availChain(virtioNetRxQ)
		if !ok {
			return
		}
		_, in := splitChain(chain)
		packet := make([]byte, virtioNetHdrLen+len(v.pending[0]))
		copy(packet[virtioNetHdrLen:], v.pending[0])
		v.pending = v.pending[1:]

		capacity := uint32(0)
		for _, d := range in {
			capacity += d.len
		}
		if capacity < uint32(len(packet)) {
			v.logf("rx descriptor too small: %d < %d", capacity, len(packet))
			v.core.pushUsed(q, head, 0)
			continue
		}
		n, err := v.core.writeChains(in, packet)
		if err != nil {
			v.logf("write rx descriptors: %v", err)
			n = 0
		}
		v.core.pushUsed(q, head, n)
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
	var err error
	if v.conn != nil {
		err = v.conn.Close()
	}
	if v.localPath != "" {
		os.Remove(v.localPath)
	}
	return err
}

func (v *Net) setCore(c *Core) { v.core = c }
