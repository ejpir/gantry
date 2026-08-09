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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ejpir/gantry/internal/gutil"
	"github.com/ejpir/gantry/internal/netpol"
	"github.com/ejpir/gantry/internal/vnet"
	"github.com/ejpir/gantry/internal/workerconf"
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

	state := &netWorkerState{
		stack: stack, policy: policy, traffic: traffic,
		currentDigest: sha256.Sum256(cfg.Policy),
	}
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- workerproto.ServeRequestsWithOptions(control, map[string]workerproto.Handler{
			"policy.prepare":   state.preparePolicy,
			"policy.commit":    state.commitPolicy,
			"policy.abort":     state.abortPolicy,
			"policy.status":    state.policyStatus,
			"port.publish":     state.publishPort,
			"port.unpublish":   state.unpublishPort,
			"port.list":        state.listPorts,
			"traffic.snapshot": state.trafficSnapshot,
			"shutdown":         state.shutdown,
		}, workerproto.ServeOptions{OrderedOps: map[string]bool{
			"policy.prepare": true,
			"policy.commit":  true,
			"policy.abort":   true,
			"policy.status":  true,
		}})
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
// the policy transaction (prepare/commit/abort by generation) must be
// atomic with respect to concurrent control requests.
type netWorkerState struct {
	stack         *vnet.Stack
	policy        *netpol.Policy // stable holder attached to the pumps
	currentTxn    string
	currentDigest [sha256.Size]byte
	pending       *netpol.Policy // prepared, awaiting commit
	pendingTxn    string
	pendingDigest [sha256.Size]byte
	gen           uint64
	pendGen       uint64
	traffic       *netpol.TrafficRecorder
	// shutdownRequested distinguishes a supervisor's graceful stop from
	// a torn data link when both race the serve loop below.
	shutdownRequested atomic.Bool
	mu                sync.Mutex
}

type policyPrepareRequest struct {
	Generation  uint64          `json:"generation"`
	Transaction string          `json:"transaction"`
	Policy      json.RawMessage `json:"policy"`
}

type policyGenerationRequest struct {
	Generation  uint64 `json:"generation,omitempty"`
	Transaction string `json:"transaction,omitempty"`
}

type policyStatusResponse struct {
	State              string `json:"state"` // current | prepared | committed | unknown
	Generation         uint64 `json:"generation"`
	Transaction        string `json:"transaction,omitempty"`
	PendingGeneration  uint64 `json:"pending_generation,omitempty"`
	PendingTransaction string `json:"pending_transaction,omitempty"`
}

func (s *netWorkerState) preparePolicy(req workerproto.Request) (any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var body policyPrepareRequest
	if err := workerproto.DecodeBody(req, &body); err != nil {
		return nil, err
	}
	if body.Transaction == "" || len(body.Transaction) > 128 {
		return nil, fmt.Errorf("invalid policy transaction ID")
	}
	digest := sha256.Sum256(body.Policy)
	// A retried request whose response was lost is a no-op only when both
	// its identity and content match. Reusing an ID for different policy
	// bytes is a protocol error, never an accidental commit.
	if body.Generation == s.gen && body.Transaction == s.currentTxn {
		if digest != s.currentDigest {
			return nil, fmt.Errorf("policy transaction %q reused with different content", body.Transaction)
		}
		return s.statusLocked(body.Transaction), nil
	}
	if s.pending != nil && body.Generation == s.pendGen && body.Transaction == s.pendingTxn {
		if digest != s.pendingDigest {
			return nil, fmt.Errorf("policy transaction %q reused with different content", body.Transaction)
		}
		return s.statusLocked(body.Transaction), nil
	}
	if s.pending != nil {
		return nil, fmt.Errorf("policy transaction %q generation %d already prepared", s.pendingTxn, s.pendGen)
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
	s.pendingTxn = body.Transaction
	s.pendingDigest = digest
	return s.statusLocked(body.Transaction), nil
}

func (s *netWorkerState) commitPolicy(req workerproto.Request) (any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var body policyGenerationRequest
	if err := workerproto.DecodeBody(req, &body); err != nil {
		return nil, err
	}
	if body.Transaction == "" || len(body.Transaction) > 128 {
		return nil, fmt.Errorf("invalid policy transaction ID")
	}
	if body.Generation == s.gen && body.Transaction == s.currentTxn {
		return s.statusLocked(body.Transaction), nil // idempotent replay
	}
	if s.pending == nil || body.Generation != s.pendGen || body.Transaction != s.pendingTxn {
		return nil, fmt.Errorf("no prepared policy transaction %q generation %d", body.Transaction, body.Generation)
	}
	if err := s.policy.Replace(s.pending); err != nil {
		return nil, err
	}
	s.currentTxn = s.pendingTxn
	s.currentDigest = s.pendingDigest
	s.pending = nil
	s.pendingTxn = ""
	s.pendingDigest = [sha256.Size]byte{}
	s.gen = body.Generation
	s.pendGen = 0
	return s.statusLocked(body.Transaction), nil
}

// abortPolicy drops a prepared transaction without touching the active
// generation. It is idempotent for an already-committed or absent transaction;
// the supervisor uses status readback to distinguish those outcomes.
func (s *netWorkerState) abortPolicy(req workerproto.Request) (any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var body policyGenerationRequest
	if err := workerproto.DecodeBody(req, &body); err != nil {
		return nil, err
	}
	if s.pending != nil && body.Generation == s.pendGen && body.Transaction == s.pendingTxn {
		s.pending = nil
		s.pendingTxn = ""
		s.pendingDigest = [sha256.Size]byte{}
		s.pendGen = 0
		return s.statusLocked(body.Transaction), nil
	}
	if s.pending != nil {
		return nil, fmt.Errorf("different policy transaction %q generation %d is prepared", s.pendingTxn, s.pendGen)
	}
	return s.statusLocked(body.Transaction), nil
}

func (s *netWorkerState) policyStatus(req workerproto.Request) (any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var body policyGenerationRequest
	if err := workerproto.DecodeBody(req, &body); err != nil {
		return nil, err
	}
	return s.statusLocked(body.Transaction), nil
}

func (s *netWorkerState) statusLocked(transaction string) policyStatusResponse {
	status := policyStatusResponse{
		State:              "unknown",
		Generation:         s.gen,
		Transaction:        s.currentTxn,
		PendingGeneration:  s.pendGen,
		PendingTransaction: s.pendingTxn,
	}
	switch {
	case transaction == "":
		status.State = "current"
	case transaction == s.currentTxn && s.currentTxn != "":
		status.State = "committed"
	case transaction == s.pendingTxn && s.pendingTxn != "":
		status.State = "prepared"
	}
	return status
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
	kill   func() error
	mu     sync.Mutex // serializes each complete policy transaction

	dead     chan struct{} // closed when the process is reaped
	deadErr  error
	deadMu   sync.RWMutex
	deadOnce sync.Once

	closeOnce sync.Once
	closeErr  error
}

// Done closes when the worker process is reaped. The daemon treats an early
// close as fatal to the sandbox: a network-worker exit is never survivable
// in-place. Err reports the exit cause without consuming the notification.
func (w *netWorker) Done() <-chan struct{} { return w.dead }

// Err reports the worker's exit state after Done closes.
func (w *netWorker) Err() error {
	w.deadMu.RLock()
	defer w.deadMu.RUnlock()
	return w.deadErr
}

func (w *netWorker) setDead(err error) {
	w.deadOnce.Do(func() {
		w.deadMu.Lock()
		w.deadErr = err
		w.deadMu.Unlock()
		close(w.dead)
	})
}

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
	w := &netWorker{cmd: cmd, data: dataSup, dead: make(chan struct{})}
	if cmd != nil {
		w.kill = func() error { return cmd.Kill() }
		go func() {
			state, err := cmd.Wait()
			if err == nil && state != nil && !state.Success() {
				err = fmt.Errorf("net-worker %s", state)
			}
			w.setDead(err)
		}()
	}
	nonce := workerproto.NewNonce()
	fail := func(err error) (*netWorker, net.Conn, error) {
		_ = ctrlSup.Close()
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
	// The Client's readLoop may only start AFTER the ready ack has been
	// consumed: the ack is an unsolicited Response{ID:0}, and a running
	// readLoop would race the explicit read for it (and treat the
	// never-issued ID as fatal). First observed on macOS, where the
	// readLoop won the race and the supervisor timed out waiting for a
	// ready the worker had already sent.
	w.client = workerproto.NewClient(ctrlSup)
	return w, dataSup, nil
}

// clientConn adapts the supervisor control conn for SendHandshake's
// net.Conn parameter (deadline support); it is already a net.Conn, this
// just keeps the signature explicit.
func clientConn(c net.Conn) net.Conn { return c }

// SetPolicy runs an idempotent prepare+commit transaction. The complete
// exchange is supervisor-serialized; generation advances only after a commit
// response or status readback proves that exact transaction committed.
func (w *netWorker) SetPolicy(policy *netpol.Policy) error {
	raw, err := netpol.Marshal(policy)
	if err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()

	if err := w.syncPolicyState(); err != nil {
		return fmt.Errorf("policy status: %w", err)
	}
	gen := w.gen + 1
	txn := hex.EncodeToString(workerproto.NewNonce())
	prepare := policyPrepareRequest{Generation: gen, Transaction: txn, Policy: raw}
	if err := w.client.Call("policy.prepare", prepare, nil); err != nil {
		// A timeout can lose the response after prepare succeeded. Read the
		// transaction state before deciding whether the active policy changed.
		status, statusErr := w.readPolicyStatus(txn)
		if statusErr != nil {
			return errors.Join(fmt.Errorf("policy prepare: %w", err),
				fmt.Errorf("policy status after prepare: %w", statusErr))
		}
		w.gen = status.Generation
		switch status.State {
		case "committed":
			return nil
		case "prepared":
			// Continue with the same transaction ID and generation.
		default:
			return fmt.Errorf("policy prepare: %w", err)
		}
	}
	return w.commitPolicyTransaction(gen, txn)
}

// syncPolicyState reconciles the supervisor generation with the worker and
// clears a prepared transaction left by a prior failed call. Preparation does
// not mutate the active policy, so aborting it preserves failure atomicity.
func (w *netWorker) syncPolicyState() error {
	status, err := w.readPolicyStatus("")
	if err != nil {
		return err
	}
	w.gen = status.Generation
	if status.PendingTransaction == "" {
		return nil
	}
	abort := policyGenerationRequest{
		Generation: status.PendingGeneration, Transaction: status.PendingTransaction,
	}
	if err := w.client.Call("policy.abort", abort, nil); err != nil {
		after, statusErr := w.readPolicyStatus("")
		if statusErr == nil {
			w.gen = after.Generation
			if after.PendingTransaction == "" {
				return nil // abort response was lost
			}
		}
		return errors.Join(fmt.Errorf("abort stale policy transaction: %w", err), statusErr)
	}
	return nil
}

func (w *netWorker) readPolicyStatus(transaction string) (policyStatusResponse, error) {
	var status policyStatusResponse
	err := w.client.Call("policy.status", policyGenerationRequest{Transaction: transaction}, &status)
	return status, err
}

func (w *netWorker) commitPolicyTransaction(gen uint64, txn string) error {
	req := policyGenerationRequest{Generation: gen, Transaction: txn}
	var failures []error
	var lastStatus *policyStatusResponse
	for attempt := 0; attempt < 2; attempt++ {
		if err := w.client.Call("policy.commit", req, nil); err == nil {
			w.gen = gen
			return nil
		} else {
			failures = append(failures, fmt.Errorf("policy commit: %w", err))
		}
		status, err := w.readPolicyStatus(txn)
		if err != nil {
			failures = append(failures, fmt.Errorf("policy status after commit: %w", err))
			continue
		}
		lastStatus = &status
		w.gen = status.Generation
		switch status.State {
		case "committed":
			return nil // commit response was lost
		case "prepared":
			continue // retry the same idempotent commit
		case "unknown":
			if status.Generation < gen {
				return errors.Join(failures...) // previous policy is still active
			}
			return w.stopAfterAmbiguousPolicy(errors.Join(failures...))
		default:
			return w.stopAfterAmbiguousPolicy(errors.Join(failures...))
		}
	}

	if lastStatus != nil && lastStatus.State == "prepared" {
		// Both commit attempts failed before applying. An acknowledged abort
		// normally proves the previous generation remains active. Decode its
		// status as well: a commit response and its immediate status response
		// can both be lost even though the commit applied, in which case abort
		// is an idempotent readback of the committed transaction.
		var status policyStatusResponse
		if err := w.client.Call("policy.abort", req, &status); err != nil {
			failures = append(failures, fmt.Errorf("abort failed policy transaction: %w", err))
			var statusErr error
			status, statusErr = w.readPolicyStatus(txn)
			if statusErr != nil {
				failures = append(failures, fmt.Errorf("policy status after abort: %w", statusErr))
				return w.stopAfterAmbiguousPolicy(errors.Join(failures...))
			}
		}
		w.gen = status.Generation
		switch {
		case status.State == "committed":
			return nil
		case status.State == "unknown" && status.Generation < gen:
			return errors.Join(failures...)
		default:
			failures = append(failures, fmt.Errorf(
				"policy transaction %q remained %s after abort (generation %d)",
				txn, status.State, status.Generation))
			return w.stopAfterAmbiguousPolicy(errors.Join(failures...))
		}
	}
	return w.stopAfterAmbiguousPolicy(errors.Join(failures...))
}

// stopAfterAmbiguousPolicy fails closed. If neither commit nor status replies,
// the supervisor cannot honestly claim which policy the worker enforces; the
// sandbox lifecycle will observe worker death and terminate instead of running
// with divergent control-plane state.
func (w *netWorker) stopAfterAmbiguousPolicy(cause error) error {
	stopErr := w.Close()
	return errors.Join(cause, fmt.Errorf("network policy state ambiguous; network worker stopped"), stopErr)
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
// escalating to a kill after a bounded wait. It is idempotent: failure
// handling and deferred sandbox cleanup may call it concurrently.
func (w *netWorker) Close() error {
	w.closeOnce.Do(func() {
		if w.client != nil {
			_ = w.client.CallWithTimeout("shutdown", nil, nil, 5*time.Second)
			_ = w.client.Close()
		}
		if w.data != nil {
			_ = w.data.Close()
		}
		if w.kill != nil {
			select {
			case <-w.dead:
				w.closeErr = w.Err()
			case <-time.After(5 * time.Second):
				_ = w.kill()
				<-w.dead
				w.closeErr = w.Err()
			}
		} else if w.dead != nil {
			// In-process tests have no process to reap. Preserve a published
			// terminal error without waiting forever on a live helper.
			select {
			case <-w.dead:
				w.closeErr = w.Err()
			default:
			}
		}
	})
	return w.closeErr
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
	// Confinement is the _vmm-worker's VERIFIED confinement report
	// (docs/worker-confinement.md schema v2): per-property states as
	// probed inside the confined process, never platform claims. Nil
	// for monolithic boots and workers too old to report.
	Confinement *workerconf.Report `json:"confinement,omitempty"`
}

// writeIsolationState persists the honest effective state for CLI/TUI and
// runtime inspection. splitVMM reports whether the guest runs in a
// _vmm-worker.
func writeIsolationState(dir string, cfg RunConfig, nw *Network, splitVMM bool, conf *workerconf.Report) error {
	st := isolationState{
		Version:            1,
		Topology:           "monolithic",
		Platform:           runtime.GOOS,
		NetworkBoundary:    "unavailable", // confinement lands in Phase 2b
		FilesystemBoundary: "unavailable",
		ProcessBoundary:    "unavailable",
	}
	degraded := append([]string(nil), nw.Degraded...)
	if conf != nil {
		st.Confinement = conf
		// Fill the boundary fields from the worker's verified probe
		// states instead of the blanket "unavailable".
		st.NetworkBoundary = conf.Property(workerconf.PropNetDial).State
		st.FilesystemBoundary = conf.Property(workerconf.PropFSRead).State
		st.ProcessBoundary = conf.Property(workerconf.PropExec).State
		if st.ProcessBoundary == workerconf.StateEnforced {
			// Executing a new image and reaching an existing process are
			// separate authorities. Aggregate only the process-access property
			// each platform actually probes.
			switch conf.Platform {
			case "linux":
				st.ProcessBoundary = conf.Property(workerconf.PropProcEnum).State
			case "darwin":
				st.ProcessBoundary = conf.Property(workerconf.PropProcSignal).State
			}
		}
	}
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
		// boundary: platform confinement is what turns the split into an
		// enforced boundary. Report the verified per-property outcome.
		switch {
		case conf == nil:
			degraded = append(degraded, "worker confinement report unavailable")
		case !conf.Applied:
			degraded = append(degraded, "worker confinement not applied: "+strings.Join(conf.Notes, "; "))
		default:
			for _, p := range conf.Results {
				if p.State != workerconf.StateEnforced && p.State != workerconf.StateDisabled {
					degraded = append(degraded, "worker confinement: "+p.Property+" "+p.State)
				}
			}
		}
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
