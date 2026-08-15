// Package networkworker owns the untrusted _net-worker child runtime and its
// private control protocol. Process spawning, supervision, and the RPC client
// remain in internal/sandbox.
package networkworker

import (
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"sync"

	"github.com/ejpir/gantry/internal/netpol"
	"github.com/ejpir/gantry/internal/vnet"
	"github.com/ejpir/gantry/internal/workerproto"
)

// ---------------------------------------------------------------------------
// worker side
// ---------------------------------------------------------------------------

// Cmd is the hidden `gantry _net-worker` entry point. The role
// argument carries no authority: the worker refuses to run unless it
// receives a valid handshake and nonce on the inherited descriptors
// (fd 3 = control, fd 4 = data).
func Cmd() int {
	control, err := workerproto.InheritedConn(3, "control")
	if err != nil {
		fmt.Fprintln(os.Stderr, "net-worker:", err)
		return 1
	}
	data, err := workerproto.InheritedConn(4, "data")
	if err != nil {
		_ = control.Close()
		fmt.Fprintln(os.Stderr, "net-worker:", err)
		return 1
	}
	if err := Run(control, data); err != nil {
		fmt.Fprintln(os.Stderr, "net-worker:", err)
		return 1
	}
	return 0
}

// Run serves the network-worker lifecycle on the given channels
// until graceful shutdown, peer death, or a fatal protocol error. It is
// transport-agnostic so tests can drive it over net.Pipe.
func Run(control, data net.Conn) (retErr error) {
	defer func() { _ = control.Close() }()
	defer func() { _ = data.Close() }()

	var cfg Config
	nonce, err := workerproto.ServeHandshake(control, workerproto.RoleNet, &cfg)
	if err != nil {
		return err
	}

	hw, err := net.ParseMAC(cfg.GuestMAC)
	if err != nil || len(hw) != 6 {
		return fmt.Errorf("bootstrap: guest MAC %q", cfg.GuestMAC)
	}
	var mac [6]byte
	copy(mac[:], hw)
	policy, err := netpol.Parse(cfg.Policy)
	if err != nil {
		return fmt.Errorf("bootstrap: %w", err)
	}
	if cfg.Debug {
		_ = os.Setenv("GANTRY_DEBUG_NET", "1")
	}
	// Authenticate the independent data channel before applying irreversible
	// confinement or opening static host listeners. No guest frame is accepted
	// until the nonce proves both inherited channels belong to this launch.
	if err := workerproto.ReadNonce(data, nonce); err != nil {
		return err
	}
	confinement, err := ApplyConfinement(cfg, control, data)
	if err != nil {
		_ = workerproto.WriteMessage(control, BootAck{
			Error:       err.Error(),
			Confinement: confinement,
		})
		return err
	}
	stack, err := vnet.Start(mac, cfg.Forwards)
	if err != nil {
		_ = workerproto.WriteMessage(control, BootAck{
			Error:       err.Error(),
			Confinement: confinement,
		})
		return fmt.Errorf("bootstrap: %w", err)
	}
	defer stack.Close()
	dev, err := stack.Dial()
	if err != nil {
		_ = workerproto.WriteMessage(control, BootAck{
			Error:       err.Error(),
			Confinement: confinement,
		})
		return fmt.Errorf("bootstrap: %w", err)
	}
	defer func() { _ = dev.Close() }()
	// The confined worker retains counters in memory only. The trusted
	// supervisor pulls bounded snapshots and owns durable sandbox state.
	traffic := netpol.NewTrafficRecorder("")
	defer traffic.Close()

	if err := workerproto.WriteMessage(control, BootAck{OK: true, Confinement: confinement}); err != nil {
		return err
	}

	// Egress: frames from the VMM are policy-checked and observed BEFORE
	// reaching the netstack; drops are silent, like any Ethernet drop.
	// Ingress: DNS responses are observed (dynamic allowances + traffic
	// names) before reaching the guest. The pumps move one frame at a
	// time with no intermediate queue, so memory stays bounded and
	// backpressure propagates to the virtio ring exactly as it did over
	// the monolithic in-process pipe. A dying pump means a dead data
	// link — malformed framing or a vanished VMM — which is FATAL to
	// the worker: the supervisor then fails the sandbox rather than run
	// a guest with no policy enforcement point.
	type pumpFailure struct {
		direction string
		err       error
	}
	pumpDead := make(chan pumpFailure, 1)
	var pumpOnce sync.Once
	dead := func(direction string, err error) {
		pumpOnce.Do(func() { pumpDead <- pumpFailure{direction: direction, err: err} })
	}
	go func() {
		err := pumpFrames(dev, data, func(frame []byte) bool {
			allowed := policy.MatchTX(frame)
			traffic.ObserveTX(frame, allowed)
			return allowed
		})
		dead("egress (VMM to netstack)", err)
	}()
	go func() {
		err := pumpFrames(data, dev, func(frame []byte) bool {
			policy.ObserveRX(frame)
			traffic.ObserveRX(frame)
			return true
		})
		dead("ingress (netstack to VMM)", err)
	}()

	state := &state{
		stack: stack, policy: policy, traffic: traffic,
		currentDigest: sha256.Sum256(cfg.Policy),
	}
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- workerproto.ServeRequestsWithOptions(control, map[string]workerproto.Handler{
			OpPolicyPrepare:   state.preparePolicy,
			OpPolicyCommit:    state.commitPolicy,
			OpPolicyAbort:     state.abortPolicy,
			OpPolicyStatus:    state.policyStatus,
			OpPortPublish:     state.publishPort,
			OpPortUnpublish:   state.unpublishPort,
			OpPortStatus:      state.portStatus,
			OpPortList:        state.listPorts,
			OpTrafficSnapshot: state.trafficSnapshot,
			OpShutdown:        state.shutdown,
		}, workerproto.ServeOptions{OrderedOps: map[string]bool{
			OpPolicyPrepare: true,
			OpPolicyCommit:  true,
			OpPolicyAbort:   true,
			OpPolicyStatus:  true,
			OpPortPublish:   true,
			OpPortUnpublish: true,
			OpPortStatus:    true,
			OpPortList:      true,
		}})
	}()
	select {
	case err := <-serveErr:
		return err
	case failure := <-pumpDead:
		// Data link died: unwind the serve loop (EOF) and report fatal
		// — unless the supervisor's graceful shutdown raced us, which
		// is the normal Close path (shutdown RPC, THEN channels close).
		_ = control.Close()
		<-serveErr
		if state.shutdownRequested.Load() {
			return nil
		}
		return fmt.Errorf("network %s pump failed: %w", failure.direction, failure.err)
	}
}

// pumpFrames copies QEMU-framed Ethernet from src to dst, admitting a
// frame only when admit returns true. Any framing violation or transport
// error closes BOTH ends: a malformed peer must not leave the sibling
// pump blocked on a half-live link. One frame in flight, no queues —
// buffering is the kernel socket buffer plus the netstack's own, both
// bounded.
func pumpFrames(dst, src net.Conn, admit func(frame []byte) bool) error {
	defer func() { _ = dst.Close() }()
	defer func() { _ = src.Close() }()
	buf := make([]byte, workerproto.MaxFrame)
	var writer workerproto.FrameWriter
	for {
		n, err := workerproto.ReadFrame(src, buf)
		if err != nil {
			return fmt.Errorf("read frame: %w", err)
		}
		frame := buf[:n]
		if !admit(frame) {
			continue // policy drop: silent, like any Ethernet drop
		}
		if err := writer.WriteFrame(dst, frame); err != nil {
			return fmt.Errorf("write frame: %w", err)
		}
	}
}
