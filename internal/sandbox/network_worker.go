package sandbox

// Split network worker (Phase 1 of docs/vmm-network-isolation.md): the
// embedded netstack, egress policy, traffic accounting, and published
// port listeners live in a re-executed `gantry _net-worker` process. The
// supervisor (daemon) talks to it over two inherited socketpairs:
//
//   - control: workerproto handshake + bounded request/response
//     (policy transactions, port ops, traffic snapshots, shutdown);
//   - data: QEMU-framed Ethernet, launched with a nonce cross-check,
//     carrying NO control information.
//
// The virtio-net device in the VMM/supervisor process attaches to the
// supervisor end of the data pair with policy/traffic NIL — enforcement
// and observation moved to the worker side of the link, so the guest's
// frames are policy-checked only after crossing the process boundary.
//
// Phase 1 improves fault isolation and establishes the data/control
// split. It does NOT yet satisfy the compromised-VMM objective (the VMM
// still shares the supervisor process); Linux confinement is Phase 2.

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ejpir/gantry/internal/gutil"
	"github.com/ejpir/gantry/internal/netpol"
	"github.com/ejpir/gantry/internal/vnet"
	"github.com/ejpir/gantry/internal/workerproto"
)

// netWorkerConfig is the bootstrap payload the supervisor hands the
// network worker over the control handshake. Everything is already
// parsed and normalized: the worker never opens a user-selected path on
// its own authority (TrafficPath is the one delegated file, inside the
// sandbox state directory; Phase 2 replaces it with a pre-opened FD).
type netWorkerConfig struct {
	GuestMAC    string            `json:"guest_mac"`
	Forwards    map[string]string `json:"forwards,omitempty"`
	Policy      json.RawMessage   `json:"policy"` // normalized file-form JSON (netpol.Marshal)
	TrafficPath string            `json:"traffic_path"`
	Debug       bool              `json:"debug"`
	PcapPath    string            `json:"pcap_path,omitempty"`
}

// ---------------------------------------------------------------------------
// worker side
// ---------------------------------------------------------------------------

// CmdNetWorker is the hidden `gantry _net-worker` entry point. The role
// argument carries no authority: the worker refuses to run unless it
// receives a valid handshake and nonce on the inherited descriptors
// (fd 3 = control, fd 4 = data).
func CmdNetWorker() int {
	control, err := inheritedConn(3, "control")
	if err != nil {
		fmt.Fprintln(os.Stderr, "net-worker:", err)
		return 1
	}
	data, err := inheritedConn(4, "data")
	if err != nil {
		fmt.Fprintln(os.Stderr, "net-worker:", err)
		return 1
	}
	if err := runNetWorker(control, data); err != nil {
		fmt.Fprintln(os.Stderr, "net-worker:", err)
		return 1
	}
	return 0
}

// runNetWorker serves the network-worker lifecycle on the given channels
// until graceful shutdown, peer death, or a fatal protocol error. It is
// transport-agnostic so tests can drive it over net.Pipe.
func runNetWorker(control, data net.Conn) (retErr error) {
	defer func() { _ = control.Close() }()
	defer func() { _ = data.Close() }()

	var cfg netWorkerConfig
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
	if cfg.PcapPath != "" {
		_ = os.Setenv("GANTRY_NET_PCAP", cfg.PcapPath)
	}
	stack, err := vnet.Start(mac, cfg.Forwards)
	if err != nil {
		return fmt.Errorf("bootstrap: %w", err)
	}
	defer stack.Close()
	dev, err := stack.Dial()
	if err != nil {
		return fmt.Errorf("bootstrap: %w", err)
	}
	defer func() { _ = dev.Close() }()
	traffic := netpol.NewTrafficRecorder(cfg.TrafficPath)
	defer traffic.Close()

	// The data channel must prove it belongs to THIS launch before a
	// single frame crosses: a cross-wired spawn fails here, before the
	// netstack is reachable from the wrong VMM.
	if err := workerproto.ReadNonce(data, nonce); err != nil {
		return err
	}
	if err := workerproto.WriteMessage(control, workerproto.Response{ID: 0, OK: true}); err != nil {
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
	pumpDead := make(chan struct{})
	var pumpOnce sync.Once
	dead := func() { pumpOnce.Do(func() { close(pumpDead) }) }
	go func() {
		pumpFrames(dev, data, func(frame []byte) bool {
			allowed := policy.MatchTX(frame)
			traffic.ObserveTX(frame, allowed)
			return allowed
		})
		dead()
	}()
	go func() {
		pumpFrames(data, dev, func(frame []byte) bool {
			policy.ObserveRX(frame)
			traffic.ObserveRX(frame)
			return true
		})
		dead()
	}()

	state := &netWorkerState{stack: stack, policy: policy, current: policy, traffic: traffic}
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- workerproto.ServeRequests(control, map[string]workerproto.Handler{
			"policy.prepare":   state.preparePolicy,
			"policy.commit":    state.commitPolicy,
			"policy.rollback":  state.rollbackPolicy,
			"port.publish":     state.publishPort,
			"port.unpublish":   state.unpublishPort,
			"port.list":        state.listPorts,
			"traffic.snapshot": state.trafficSnapshot,
			"shutdown":         state.shutdown,
		})
	}()
	select {
	case err := <-serveErr:
		return err
	case <-pumpDead:
		// Data link died: unwind the serve loop (EOF) and report fatal
		// — unless the supervisor's graceful shutdown raced us, which
		// is the normal Close path (shutdown RPC, THEN channels close).
		_ = control.Close()
		<-serveErr
		if state.shutdownRequested.Load() {
			return nil
		}
		return fmt.Errorf("network data link closed")
	}
}

// pumpFrames copies QEMU-framed Ethernet from src to dst, admitting a
// frame only when admit returns true. Any framing violation or transport
// error closes BOTH ends: a malformed peer must not leave the sibling
// pump blocked on a half-live link. One frame in flight, no queues —
// buffering is the kernel socket buffer plus the netstack's own, both
// bounded.
func pumpFrames(dst, src net.Conn, admit func(frame []byte) bool) {
	buf := make([]byte, workerproto.MaxFrame)
	for {
		n, err := workerproto.ReadFrame(src, buf)
		if err != nil {
			_ = dst.Close()
			_ = src.Close()
			return
		}
		frame := buf[:n]
		if !admit(frame) {
			continue // policy drop: silent, like any Ethernet drop
		}
		if err := workerproto.WriteFrame(dst, frame); err != nil {
			_ = dst.Close()
			_ = src.Close()
			return
		}
	}
}

// netWorkerState holds the worker's mutable live state behind one mutex:
// the policy transaction (prepare/commit/rollback by generation) must be
// atomic with respect to concurrent control requests, and ServeRequests
// is sequential anyway.
type netWorkerState struct {
	stack   *vnet.Stack
	policy  *netpol.Policy // stable holder attached to the pumps
	current *netpol.Policy // active generation's policy
	pending *netpol.Policy // prepared, awaiting commit
	rolled  *netpol.Policy // previous generation, for rollback
	gen     uint64
	pendGen uint64
	traffic *netpol.TrafficRecorder
	// shutdownRequested distinguishes a supervisor's graceful stop from
	// a torn data link when both race the serve loop below.
	shutdownRequested atomic.Bool
	mu                sync.Mutex
}

type policyPrepareRequest struct {
	Generation uint64          `json:"generation"`
	Policy     json.RawMessage `json:"policy"`
}

type policyGenerationRequest struct {
	Generation uint64 `json:"generation"`
}

func (s *netWorkerState) preparePolicy(req workerproto.Request) (any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var body policyPrepareRequest
	if err := workerproto.DecodeBody(req, &body); err != nil {
		return nil, err
	}
	if body.Generation != s.gen+1 {
		return nil, fmt.Errorf("policy generation %d out of order (current %d)", body.Generation, s.gen)
	}
	next, err := netpol.Parse(body.Policy)
	if err != nil {
		return nil, err
	}
	s.pending = next
	s.pendGen = body.Generation
	return nil, nil
}

func (s *netWorkerState) commitPolicy(req workerproto.Request) (any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var body policyGenerationRequest
	if err := workerproto.DecodeBody(req, &body); err != nil {
		return nil, err
	}
	if s.pending == nil || body.Generation != s.pendGen {
		return nil, fmt.Errorf("no prepared policy for generation %d", body.Generation)
	}
	if err := s.policy.Replace(s.pending); err != nil {
		return nil, err
	}
	s.rolled = s.current
	s.current = s.pending
	s.pending = nil
	s.gen = body.Generation
	return nil, nil
}

func (s *netWorkerState) rollbackPolicy(req workerproto.Request) (any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending != nil {
		// Roll back a prepared-but-uncommitted policy: just drop it.
		s.pending = nil
		return nil, nil
	}
	if s.rolled == nil {
		return nil, fmt.Errorf("no previous policy generation to roll back to")
	}
	if err := s.policy.Replace(s.rolled); err != nil {
		return nil, err
	}
	s.current = s.rolled
	s.rolled = nil
	s.gen++
	return nil, nil
}

type portPublishRequest struct {
	Proto  string `json:"proto"`
	Local  string `json:"local"`
	Remote string `json:"remote"`
}

type portUnpublishRequest struct {
	Proto string `json:"proto"`
	Local string `json:"local"`
}

func (s *netWorkerState) publishPort(req workerproto.Request) (any, error) {
	var body portPublishRequest
	if err := workerproto.DecodeBody(req, &body); err != nil {
		return nil, err
	}
	return nil, s.stack.Publish(body.Proto, body.Local, body.Remote)
}

func (s *netWorkerState) unpublishPort(req workerproto.Request) (any, error) {
	var body portUnpublishRequest
	if err := workerproto.DecodeBody(req, &body); err != nil {
		return nil, err
	}
	return nil, s.stack.Unpublish(body.Proto, body.Local)
}

func (s *netWorkerState) listPorts(workerproto.Request) (any, error) {
	return s.stack.Forwards()
}

func (s *netWorkerState) trafficSnapshot(workerproto.Request) (any, error) {
	return s.traffic.Snapshot(), nil
}

func (s *netWorkerState) shutdown(workerproto.Request) (any, error) {
	s.shutdownRequested.Store(true)
	return nil, workerproto.ErrShutdown
}

// ---------------------------------------------------------------------------
// supervisor side
// ---------------------------------------------------------------------------

// netWorker is the supervisor's handle on the spawned worker process and
// implements NetworkBackend over RPC.
type netWorker struct {
	cmd    *os.Process // nil when driven in-process (tests)
	client *workerproto.Client
	data   net.Conn
	gen    uint64
	done   chan error // process exit / wait result; closed semantics via buffer 1
	kill   func() error
	mu     sync.Mutex // gen counter; Call itself is serialized internally
}

// Done reports a channel that receives the worker's exit cause (nil for a
// clean shutdown). The daemon treats any early delivery as fatal to the
// sandbox: a network-worker exit is never survivable in-place.
func (w *netWorker) Done() <-chan error { return w.done }

// startNetWorker spawns the worker process, performs the handshake and
// nonce cross-check, and returns the ready backend plus the supervisor
// end of the data channel (which the virtio-net device attaches to).
func startNetWorker(cfg netWorkerConfig) (*netWorker, net.Conn, error) {
	// The worker's stderr lands next to its traffic log: bootstrap
	// failures leave their own postmortem (worker-net.log).
	ctrlSup, dataSup, cmd, err := spawnNetWorkerProcess(filepath.Join(filepath.Dir(cfg.TrafficPath), "worker-net.log"))
	if err != nil {
		return nil, nil, err
	}
	w := &netWorker{cmd: cmd, data: dataSup, done: make(chan error, 1)}
	if cmd != nil {
		w.kill = func() error { return cmd.Kill() }
		go func() {
			state, err := cmd.Wait()
			if err != nil {
				w.done <- err
				return
			}
			w.done <- fmt.Errorf("exit status %s", state)
		}()
	}
	client := workerproto.NewClient(ctrlSup)
	nonce := workerproto.NewNonce()
	fail := func(err error) (*netWorker, net.Conn, error) {
		_ = client.Close()
		_ = dataSup.Close()
		if w.kill != nil {
			_ = w.kill()
		}
		return nil, nil, err
	}
	if err := workerproto.SendHandshake(clientConn(ctrlSup), workerproto.RoleNet, nonce, cfg); err != nil {
		return fail(fmt.Errorf("net-worker handshake: %w", err))
	}
	if err := workerproto.WriteNonce(dataSup, nonce); err != nil {
		return fail(fmt.Errorf("net-worker nonce: %w", err))
	}
	var ack workerproto.Response
	_ = ctrlSup.SetReadDeadline(time.Now().Add(15 * time.Second))
	if err := workerproto.ReadMessage(ctrlSup, &ack); err != nil {
		return fail(fmt.Errorf("net-worker ready: %w", err))
	}
	_ = ctrlSup.SetReadDeadline(time.Time{})
	if !ack.OK {
		return fail(fmt.Errorf("net-worker bootstrap failed"))
	}
	w.client = client
	return w, dataSup, nil
}

// clientConn adapts the supervisor control conn for SendHandshake's
// net.Conn parameter (deadline support); it is already a net.Conn, this
// just keeps the signature explicit.
func clientConn(c net.Conn) net.Conn { return c }

// SetPolicy runs the design doc's transaction as prepare+commit in one
// supervisor-serialized sequence; the manager's rollback path simply
// calls SetPolicy again with the previous policy (one more generation).
func (w *netWorker) SetPolicy(policy *netpol.Policy) error {
	raw, err := netpol.Marshal(policy)
	if err != nil {
		return err
	}
	w.mu.Lock()
	w.gen++
	gen := w.gen
	w.mu.Unlock()
	if err := w.client.Call("policy.prepare", policyPrepareRequest{Generation: gen, Policy: raw}, nil); err != nil {
		return fmt.Errorf("policy prepare: %w", err)
	}
	if err := w.client.Call("policy.commit", policyGenerationRequest{Generation: gen}, nil); err != nil {
		_ = w.client.Call("policy.rollback", nil, nil) // drop the dangling prepare
		return fmt.Errorf("policy commit: %w", err)
	}
	return nil
}

func (w *netWorker) Publish(proto, local, remote string) error {
	return w.client.Call("port.publish", portPublishRequest{Proto: proto, Local: local, Remote: remote}, nil)
}

func (w *netWorker) Unpublish(proto, local string) error {
	return w.client.Call("port.unpublish", portUnpublishRequest{Proto: proto, Local: local}, nil)
}

func (w *netWorker) Forwards() ([]vnet.Forward, error) {
	var out []vnet.Forward
	err := w.client.Call("port.list", nil, &out)
	return out, err
}

// TrafficSnapshot fetches the live counters (diagnostics; the TUI keeps
// reading the file the worker maintains).
func (w *netWorker) TrafficSnapshot() (netpol.TrafficSnapshot, error) {
	var out netpol.TrafficSnapshot
	err := w.client.Call("traffic.snapshot", nil, &out)
	return out, err
}

// Close asks the worker to shut down gracefully (it flushes traffic and
// tears the stack down), then closes both channels and reaps the process,
// escalating to a kill after a bounded wait.
func (w *netWorker) Close() error {
	if w.client != nil {
		w.client.Timeout = 5 * time.Second
		_ = w.client.Call("shutdown", nil, nil)
		_ = w.client.Close()
	}
	if w.data != nil {
		_ = w.data.Close()
	}
	if w.kill != nil {
		select {
		case <-w.done:
		case <-time.After(5 * time.Second):
			_ = w.kill()
			<-w.done
		}
	}
	return nil
}

// netWorkerTrafficDebug mirrors GANTRY_DEBUG_NET into the bootstrap config.
func netWorkerTrafficDebug() bool { return gutil.EnvOr("GANTRY_DEBUG_NET", "MINIVM_DEBUG_NET") != "" }

// ---------------------------------------------------------------------------
// isolation state reporting
// ---------------------------------------------------------------------------

// isolationState is the machine-readable effective isolation of a running
// sandbox (dir/isolation.json, 0600). Per the design doc: report only
// successfully installed controls — never infer security state from the
// requested flag. Phase 1 establishes the process split but no boundary
// claims yet; every "enforced" value arrives with later phases.
type isolationState struct {
	Version            int      `json:"version"`
	Topology           string   `json:"topology"` // "monolithic" | "split-net" | "split-vmm" | "split-net+split-vmm"
	Platform           string   `json:"platform"`
	NetworkBoundary    string   `json:"networkBoundary"`
	FilesystemBoundary string   `json:"filesystemBoundary"`
	ProcessBoundary    string   `json:"processBoundary"`
	Degraded           []string `json:"degraded"`
}

// writeIsolationState persists the honest effective state for CLI/TUI and
// runtime inspection. splitVMM reports whether the guest runs in a
// _vmm-worker.
func writeIsolationState(dir string, cfg RunConfig, nw *Network, splitVMM bool) error {
	st := isolationState{
		Version:            1,
		Topology:           "monolithic",
		Platform:           runtime.GOOS,
		NetworkBoundary:    "unavailable", // confinement lands in Phase 2b
		FilesystemBoundary: "unavailable",
		ProcessBoundary:    "unavailable",
	}
	degraded := append([]string(nil), nw.Degraded...)
	switch cfg.ProcessIsolation {
	case "off":
		degraded = append(degraded, "process isolation disabled by configuration")
	default:
		if nw.Split {
			st.Topology = "split-net"
		}
		if splitVMM {
			if st.Topology == "split-net" {
				st.Topology = "split-net+split-vmm"
			} else {
				st.Topology = "split-vmm"
			}
		}
		// The process split alone is fault isolation, NOT a security
		// boundary: platform confinement (Phase 2b) is what turns the
		// split into an enforced boundary. Until then nothing here may
		// report "enforced".
		degraded = append(degraded, "platform confinement not yet implemented (Phase 2b)")
		if !nw.Split && cfg.Net && cfg.GVProxy == "" {
			degraded = append(degraded, "network worker not established")
		}
		if !splitVMM && cfg.ProcessIsolation != "" {
			degraded = append(degraded, "vmm worker not established")
		}
	}
	st.Degraded = degraded
	raw, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "isolation.json"), append(raw, '\n'), 0o600)
}

// DbgStartNetWorker is a TEMPORARY diagnostic export for cmd/dbgnetspawn:
// the production spawn path with no test hooks.
func DbgStartNetWorker(mac string, policyJSON []byte, dir string) (*netWorker, net.Conn, error) {
	return startNetWorker(netWorkerConfig{
		GuestMAC:    mac,
		Policy:      policyJSON,
		TrafficPath: filepath.Join(dir, netpol.TrafficFileName),
	})
}
