//go:build linux || darwin

package sandbox

// Phase 2a-iii of docs/vmm-network-isolation.md: the _vmm-worker process.
// The hypervisor, guest RAM, virtio device frontends, disk image I/O, and
// the vsock data plane move out of the supervisor into a re-executed
// worker. The supervisor keeps ctl.sock, CLI sessions, network policy,
// host sockets, and the trusted share broker that owns host roots.
//
// Channels (fixed descriptor slots, socketpairs):
//
//	fd 3  control — supervisor -> worker RPC (workerproto):
//	      vm.wait, vm.close, vsock.connect, shutdown
//	fd 4  bridge — worker -> supervisor RPC: vsock.forward (guest
//	      dial-back needs a supervisor-owned host socket)
//	fd 5  fd channel — SCM_RIGHTS transfers, ALL supervisor -> worker,
//	      token-correlated with RPCs on either RPC channel; the first
//	      32 bytes are the launch nonce (cross-wiring check)
//	fd 6  share data — bounded FUSE request/response relay to the trusted
//	      supervisor; the worker receives no host share roots or paths
//	fd 7  net data — QEMU-framed Ethernet to the net-worker (or the
//	      supervisor's in-process netstack in the degraded topology)
//	fd 8  console log (append-only)
//	fd 9+ kernel, rootfs?, DisksRO..., Disks...
//
// The worker owns no host paths: boot assets arrive as descriptors,
// vsock dial-backs are brokered by the supervisor, host->guest streams
// arrive as descriptors. This is what Phase 2b confinement builds on.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/ejpir/gantry/internal/netpol"
	"github.com/ejpir/gantry/internal/virtio"
	"github.com/ejpir/gantry/internal/vmm"
	"github.com/ejpir/gantry/internal/workerconf"
	"github.com/ejpir/gantry/internal/workerproto"
)

// vmmBootConfig travels in the workerproto handshake. Counts define the
// descriptor table layout after the fixed slots.
type vmmBootConfig struct {
	MemSize  uint64  `json:"memSize"`
	VCPUs    int     `json:"vcpus"`
	Cmdline  string  `json:"cmdline"`
	NetMAC   [6]byte `json:"netMAC"`
	GuestCID uint64  `json:"guestCID"`
	HasRoot  bool    `json:"hasRootfs"`
	// BootTimingStartUnixNano carries the daemon's diagnostic clock into
	// the split worker. Zero disables guest milestone collection.
	BootTimingStartUnixNano int64 `json:"bootTimingStartUnixNano,omitempty"`
	NDisksRO                int   `json:"nDisksRO"`
	NDisks                  int   `json:"nDisks"`
	// Policy carries the LOCAL-netstack enforcement state: in the
	// degraded topology (net-worker failed in auto, VMM split succeeded)
	// the guest's frames land on the supervisor's embedded netstack,
	// which enforces nothing — the virtio-net device in THIS worker is
	// the only enforcement point, and a nil policy there is allow-all.
	// Empty Policy means the split-net topology owns enforcement instead.
	// Traffic counters accumulate in an in-memory recorder (the worker
	// owns no host paths — confinement kills path ops); the supervisor
	// pulls them over traffic.snapshot and merges into its own recorder.
	Policy []byte `json:"policy,omitempty"`
	// Confinement is the worker confinement mode: "auto" | "required" |
	// "off" ("" = off: tests and the no-confinement fallback). ConfRoot
	// is a supervisor-created mountpoint dir for the worker's private
	// root (linux). HasKVM marks a pre-opened /dev/kvm descriptor as
	// the LAST entry of the descriptor table (confinement makes the
	// worker's /dev empty, so the hypervisor handle must be passed).
	Confinement string `json:"confinement,omitempty"`
	ConfRoot    string `json:"confRoot,omitempty"`
	HasKVM      bool   `json:"hasKVM,omitempty"`
	// WriteFiles are the pre-opened log files Seatbelt allows by
	// literal path (console log + stderr postmortem log). Never a
	// directory: the logs' parent holds trusted state (sandbox.json).
	WriteFiles []string `json:"writeFiles,omitempty"`
}

// vmmWorkerAssets are the already-open descriptors of the descriptor
// table (fd 6 onward), opened by the spawn code or the test harness.
type vmmWorkerAssets struct {
	ShareConn net.Conn // request-only capability; no host roots cross into the worker
	NetConn   net.Conn
	Console   *os.File
	Kernel    *os.File
	Rootfs    *os.File
	DisksRO   []*os.File
	Disks     []*os.File
	KVM       *os.File // pre-opened /dev/kvm; last table slot when cfg.HasKVM
}

// vmmRunnerImpl abstracts the booted machine inside the worker so tests
// can run the full worker loop without /dev/kvm.
type vmmRunnerImpl interface {
	Run() error
	Close() error
	InjectVsockConn(guestPort uint32, nc net.Conn) error
}

// realVMM adapts a prepared machine.
type realVMM struct{ m *vmm.Machine }

func (r realVMM) Run() error   { return vmm.Run(r.m) }
func (r realVMM) Close() error { return r.m.Close() }
func (r realVMM) InjectVsockConn(guestPort uint32, nc net.Conn) error {
	return r.m.InjectVsockConn(guestPort, nc)
}

// vmmWorkerBoot prepares the machine (tests swap in a fake runner).
var vmmWorkerBoot = func(opts vmm.Opts) (vmmRunnerImpl, error) {
	m, err := vmm.Prepare(opts)
	if err != nil {
		return nil, err
	}
	return realVMM{m: m}, nil
}

// Confinement hooks (tests substitute fakes; production is workerconf).
var (
	workerconfApplyFn  = workerconf.Apply
	workerconfVerifyFn = workerconf.Verify
)

// vmmKeepFDs computes the descriptor-table high-water mark: fds 0..8 are
// stdio plus the fixed slots; the asset table follows densely (kernel,
// rootfs?, DisksRO..., Disks..., kvm?).
func vmmKeepFDs(cfg vmmBootConfig) int {
	n := 9 // fds 0..8
	n++    // kernel
	if cfg.HasRoot {
		n++
	}
	n += cfg.NDisksRO + cfg.NDisks
	if cfg.HasKVM {
		n++
	}
	return n - 1 // highest surviving fd (fds are 0-indexed)
}

// ---------------------------------------------------------------- worker

// runVMMWorker is the worker-side loop. It consumes the handshake, builds
// the machine from the descriptor table, runs it, and serves control RPCs
// until shutdown or channel death. Blocking operations never run on the
// serve loop's critical path: vm.wait parks in its own handler goroutine
// (workerproto serves concurrently). assetsFn builds the asset table
// AFTER the handshake (the descriptor counts live in the boot config).
func runVMMWorker(control, bridge, fdChan net.Conn, assetsFn func(cfg vmmBootConfig) (vmmWorkerAssets, error)) (ret error) {
	defer func() {
		_ = control.Close()
		_ = bridge.Close()
		_ = fdChan.Close()
	}()
	var cfg vmmBootConfig
	nonce, err := workerproto.ServeHandshake(control, workerproto.RoleVMM, &cfg)
	if err != nil {
		return err
	}
	assets, err := assetsFn(cfg)
	if err != nil {
		return fmt.Errorf("descriptor table: %w", err)
	}
	if assets.ShareConn == nil {
		return fmt.Errorf("descriptor table: share relay is required")
	}
	defer func() { _ = assets.ShareConn.Close() }()
	if assets.NetConn != nil {
		defer func() { _ = assets.NetConn.Close() }()
	}
	// Both independent data channels carry the launch nonce first:
	// cross-wired descriptor tables die before any RPC or guest frame.
	if err := workerproto.ReadNonce(fdChan, nonce); err != nil {
		return fmt.Errorf("fd channel nonce: %w", err)
	}
	if err := workerproto.ReadNonce(assets.ShareConn, nonce); err != nil {
		return fmt.Errorf("share channel nonce: %w", err)
	}

	// Worker confinement (docs/worker-confinement.md): everything the
	// worker needs is already open as descriptors, so Apply can deny
	// the rest. The report rides the boot ack into isolation.json;
	// "required" refuses the boot when a core property is not verified
	// enforced. Fail-closed: an apply/verify error in required mode is
	// a boot refusal, never a silent degrade.
	conf := workerconf.DisabledReport(runtime.GOOS, cfg.Confinement)
	if cfg.Confinement != "" && cfg.Confinement != "off" {
		spec := workerconf.DefaultSpec(vmmKeepFDs(cfg), cfg.ConfRoot)
		// The close tier must not sever the channels this worker runs
		// on: net.FileConn DUPS each inherited conn fd, and the dup
		// (not the table slot) is the live descriptor.
		for _, c := range []net.Conn{control, bridge, fdChan, assets.ShareConn, assets.NetConn} {
			if fd, ok := workerConnFD(c); ok {
				spec.KeepFDExtra = append(spec.KeepFDExtra, fd)
			}
		}
		fmt.Fprintf(os.Stderr, "_vmm-worker: confinement %s: applying (KeepFDs=%d extra=%v ConfRoot=%q)\n", cfg.Confinement, vmmKeepFDs(cfg), spec.KeepFDExtra, cfg.ConfRoot)
		spec.WriteFiles = cfg.WriteFiles
		if rep, applyErr := workerconfApplyFn(spec); rep != nil {
			conf = *rep
			conf.Mode = cfg.Confinement
			if applyErr != nil {
				conf.Notes = append(conf.Notes, "apply: "+applyErr.Error())
			}
		} else if applyErr != nil {
			conf.Notes = append(conf.Notes, "apply: "+applyErr.Error())
		}
		fmt.Fprintf(os.Stderr, "_vmm-worker: confinement applied: %v; verifying\n", conf.Notes)
		workerconfVerifyFn(spec, &conf)
		fmt.Fprintf(os.Stderr, "_vmm-worker: confinement verified: fs-read=%s net-dial=%s exec=%s\n",
			conf.Property(workerconf.PropFSRead).State, conf.Property(workerconf.PropNetDial).State, conf.Property(workerconf.PropExec).State)
		if cfg.Confinement == "required" {
			failed := conf.Failed(requiredWorkerConfinementProperties(conf.Platform)...)
			if len(failed) > 0 {
				msg := fmt.Sprintf("process isolation required but confinement not enforced: %v", failed)
				_ = workerproto.WriteMessage(control, map[string]any{"ok": false, "error": msg, "confinement": conf})
				return fmt.Errorf("%s", msg)
			}
		}
	}

	fds := workerproto.NewFDMux(fdChan)
	bridgeClient := workerproto.NewClient(bridge)
	defer func() { _ = bridgeClient.Close() }()

	// Only the virtio-fs device frontend lives in the worker. The trusted
	// supervisor owns the real ShareHub and every host root/handle; this
	// proxy can exchange bounded FUSE IOVs but cannot issue host syscalls
	// against a delegated directory on its own.
	shareProxy, err := virtio.NewShareHubProxy(assets.ShareConn)
	if err != nil {
		return fmt.Errorf("share proxy: %w", err)
	}
	defer func() { _ = shareProxy.Close() }()

	// Local-netstack policy: fail CLOSED. A policy that cannot be parsed
	// must never degrade into an allow-all device.
	var policy *netpol.Policy
	if len(cfg.Policy) > 0 {
		policy, err = netpol.Parse(cfg.Policy)
		if err != nil {
			return fmt.Errorf("network policy: %w", err)
		}
	}
	var traffic *netpol.TrafficRecorder
	if len(cfg.Policy) > 0 {
		// Pure in-memory: confinement makes path ops impossible by
		// design; the supervisor syncs via the traffic.snapshot RPC.
		traffic = netpol.NewTrafficRecorder("")
		defer traffic.Close()
	}

	var bootTimingStart time.Time
	if cfg.BootTimingStartUnixNano != 0 {
		bootTimingStart = time.Unix(0, cfg.BootTimingStartUnixNano)
	}
	opts := vmm.Opts{
		MemSize:    cfg.MemSize,
		Kernel:     assets.Kernel,
		Rootfs:     assets.Rootfs,
		DisksRO:    assets.DisksRO,
		Disks:      assets.Disks,
		ShareProxy: shareProxy,
		NetConn:    assets.NetConn,
		NetMAC:     cfg.NetMAC,
		NetPolicy:  policy, NetTraffic: traffic,
		KVM:             assets.KVM,
		GuestCID:        cfg.GuestCID,
		VCPUs:           cfg.VCPUs,
		Cmdline:         cfg.Cmdline,
		Console:         assets.Console,
		BootTimingStart: bootTimingStart,
		VsockDial:       func(port uint32) (net.Conn, error) { return vsockForwardDial(bridgeClient, fds, port) },
		// Host->guest streams arrive as descriptors (vsock.connect), not
		// unix listeners: the worker owns no host sockets.
		VsockNoListen: true,
	}
	runner, err := vmmWorkerBoot(opts)
	// Boot ack: the supervisor learns HERE whether the machine was built
	// (a missing /dev/kvm or bad asset is a spawn error, not a dead VM).
	if err != nil {
		_ = workerproto.WriteMessage(control, map[string]any{"ok": false, "error": err.Error()})
		return err
	}
	if err := workerproto.WriteMessage(control, map[string]any{"ok": true, "confinement": conf}); err != nil {
		return fmt.Errorf("boot ack: %w", err)
	}
	state := &vmmWorkerState{runner: runner, fds: fds, policy: policy, traffic: traffic}
	vmErr := make(chan error, 1)
	go func() { vmErr <- runner.Run() }()
	state.vmErr = vmErr

	return workerproto.ServeRequests(control, map[string]workerproto.Handler{
		"vm.wait":          state.vmWait,
		"vm.close":         state.vmClose,
		"vsock.connect":    state.vsockConnect,
		"net.policy":       state.netPolicy,
		"traffic.snapshot": state.trafficSnapshot,
		"shutdown":         func(workerproto.Request) (any, error) { return nil, workerproto.ErrShutdown },
	})
}

func requiredWorkerConfinementProperties(platform string) []string {
	required := []string{
		workerconf.PropFSRead,
		workerconf.PropFSWrite,
		workerconf.PropNetDial,
		workerconf.PropExec,
	}
	// Process access is platform-specific and must be backed by a real
	// in-worker probe. Linux verifies process enumeration after entering its
	// PID namespace; Darwin verifies Seatbelt's self-only signal rule against
	// the live supervisor parent. Neither result substitutes for the other.
	switch platform {
	case "linux":
		required = append(required, workerconf.PropProcEnum)
	case "darwin":
		required = append(required, workerconf.PropProcSignal)
	}
	return required
}

// workerConnFD resolves the live descriptor behind a net.Conn (the
// net.FileConn dup), for the confinement close tier's keep list.
func workerConnFD(c net.Conn) (int, bool) {
	sc, ok := c.(syscall.Conn)
	if !ok || sc == nil {
		return 0, false
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return 0, false
	}
	fd := -1
	if err := raw.Control(func(f uintptr) { fd = int(f) }); err != nil || fd < 0 {
		return 0, false
	}
	return fd, true
}

type vmmWorkerState struct {
	runner  vmmRunnerImpl
	fds     *workerproto.FDMux
	policy  *netpol.Policy          // non-nil only in the local-netstack topology
	traffic *netpol.TrafficRecorder // in-memory; paired with policy
	vmErr   chan error
}

// netPolicyRequest carries one marshaled egress policy.
type netPolicyRequest struct {
	Policy []byte `json:"policy"`
}

// netPolicy swaps the live enforcement copy. The device reads through
// the same *Policy (Replace swaps the internal pointer), exactly like
// the monolithic localBackend path.
func (s *vmmWorkerState) netPolicy(req workerproto.Request) (any, error) {
	if s.policy == nil {
		return nil, fmt.Errorf("net.policy: no local netstack policy in this topology")
	}
	var body netPolicyRequest
	if err := json.Unmarshal(req.Body, &body); err != nil {
		return nil, fmt.Errorf("net.policy: %w", err)
	}
	next, err := netpol.Parse(body.Policy)
	if err != nil {
		return nil, fmt.Errorf("net.policy: %w", err)
	}
	return nil, s.policy.Replace(next)
}

// trafficSnapshot hands the supervisor the worker's in-memory counters.
func (s *vmmWorkerState) trafficSnapshot(workerproto.Request) (any, error) {
	if s.traffic == nil {
		return nil, fmt.Errorf("traffic.snapshot: no local netstack recorder in this topology")
	}
	return s.traffic.Snapshot(), nil
}

// vsockForwardDial bridges one guest->host vsock dial-back: the worker
// asks the supervisor (which owns all host sockets) for a conn to the
// port's listener; the conn itself crosses as a descriptor.
func vsockForwardDial(bridge *workerproto.Client, fds *workerproto.FDMux, port uint32) (net.Conn, error) {
	var token [workerproto.FDTokenLen]byte
	if _, err := rand.Read(token[:]); err != nil {
		return nil, err
	}
	// Expect BEFORE the RPC: the supervisor transfers the descriptor
	// before answering, and would otherwise block forever on a receive
	// that hasn't been registered.
	wait, err := fds.Expect(token)
	if err != nil {
		return nil, err
	}
	err = bridge.Call("vsock.forward", vsockForwardRequest{Port: port, Token: hex.EncodeToString(token[:])}, nil)
	if err != nil {
		fds.Cancel(token)
		return nil, err
	}
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	var f *os.File
	select {
	case r := <-wait:
		if r.Err != nil {
			return nil, r.Err
		}
		f = r.F
	case <-timer.C:
		fds.Cancel(token)
		return nil, fmt.Errorf("vsock.forward: descriptor never arrived")
	}
	conn, err := net.FileConn(f)
	_ = f.Close()
	if err != nil {
		return nil, err
	}
	return conn, nil
}

type vsockForwardRequest struct {
	Port  uint32 `json:"port"`
	Token string `json:"token"`
}

type vsockConnectRequest struct {
	Port  uint32 `json:"port"`
	Token string `json:"token"`
}

// vmWait parks until the VM exits; the supervisor issues exactly one,
// right after boot, as its guestErr equivalent. vmErr is buffered(1), so
// a VM that exits before vm.wait arrives is still reported.
func (s *vmmWorkerState) vmWait(workerproto.Request) (any, error) {
	err := <-s.vmErr
	out := vmWaitResponse{Err: errString(err)}
	if s.traffic != nil {
		snapshot := s.traffic.Snapshot()
		out.Traffic = &snapshot
	}
	return out, nil
}

type vmWaitResponse struct {
	Err     string                  `json:"err,omitempty"`
	Traffic *netpol.TrafficSnapshot `json:"traffic,omitempty"`
}

type vmCloseResponse struct {
	Traffic *netpol.TrafficSnapshot `json:"traffic,omitempty"`
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// vmClose flushes devices (the review-finding-5 graceful stop) and returns
// the final traffic counters while the control channel is still alive. The
// worker protocol then sends the response before unwinding the serve loop.
func (s *vmmWorkerState) vmClose(workerproto.Request) (any, error) {
	if err := s.runner.Close(); err != nil {
		return nil, err
	}
	out := vmCloseResponse{}
	if s.traffic != nil {
		snapshot := s.traffic.Snapshot()
		out.Traffic = &snapshot
	}
	return out, workerproto.ErrShutdown
}

// vsockConnect registers a host->guest stream: the descriptor (a
// socketpair end held by the supervisor's broker) becomes the host side
// of a vsock conn to the guest's listening port.
func (s *vmmWorkerState) vsockConnect(req workerproto.Request) (any, error) {
	var body vsockConnectRequest
	if err := json.Unmarshal(req.Body, &body); err != nil {
		return nil, fmt.Errorf("vsock.connect: %w", err)
	}
	token, err := hex.DecodeString(body.Token)
	if err != nil || len(token) != workerproto.FDTokenLen {
		return nil, fmt.Errorf("vsock.connect: bad token")
	}
	var tok [workerproto.FDTokenLen]byte
	copy(tok[:], token)
	f, err := s.fds.Recv(tok)
	if err != nil {
		return nil, fmt.Errorf("vsock.connect: %w", err)
	}
	conn, err := net.FileConn(f)
	_ = f.Close()
	if err != nil {
		return nil, fmt.Errorf("vsock.connect: %w", err)
	}
	if err := s.runner.InjectVsockConn(body.Port, conn); err != nil {
		return nil, fmt.Errorf("vsock.connect: %w", err)
	}
	return nil, nil
}

// ------------------------------------------------------------ supervisor

// vmmWorker is the supervisor's handle on the worker process: control
// client, fd channel (send side), bridge serve loop, and lifecycle. It
// implements vmmRunner.
type vmmWorker struct {
	proc       *os.Process
	client     *workerproto.Client // control (fd 3)
	fdChan     net.Conn            // fd 5, send side
	fdSend     sync.Mutex          // serialize SCM_RIGHTS sends
	bridge     net.Conn
	bridgeE    chan error
	share      net.Conn // fd 6 peer: supervisor side of the FUSE relay
	shareE     chan error
	stopping   chan struct{} // closed before an intentional relay teardown
	stopOnce   sync.Once
	waitMu     sync.Mutex // protects lazy lifecycle-context initialization
	waitCtx    context.Context
	waitCancel context.CancelFunc
	// Local-netstack counters live in the confined worker. Periodic pulls
	// are cancellable; vm.wait/vm.close responses furnish the final snapshot
	// before the control channel dies.
	trafficRec      *netpol.TrafficRecorder
	trafficCancel   context.CancelFunc
	trafficDone     chan struct{}
	trafficStopOnce sync.Once

	dead    chan struct{} // closed when the process is reaped
	deadErr error
	deadMu  sync.RWMutex

	closeOnce sync.Once
	closeErr  error

	confReport workerconf.Report // from the boot ack
}

// Done closes when the worker process is reaped (Err reports how).
func (w *vmmWorker) Done() <-chan struct{} { return w.dead }

// Err reports the worker's exit state after Done closes.
func (w *vmmWorker) Err() error {
	w.deadMu.RLock()
	defer w.deadMu.RUnlock()
	return w.deadErr
}

func (w *vmmWorker) setDead(err error) {
	w.deadMu.Lock()
	w.deadErr = err
	w.deadMu.Unlock()
	// Publish the stopping marker before closing the relay. ServeBroker
	// wakes because of that close and must distinguish process teardown
	// from an unexpected loss of the share channel.
	w.markStopping()
	if w.share != nil {
		_ = w.share.Close()
	}
	close(w.dead)
	w.cancelWait()
}

func (w *vmmWorker) markStopping() {
	if w != nil && w.stopping != nil {
		w.stopOnce.Do(func() { close(w.stopping) })
	}
}

func (w *vmmWorker) waitContext() context.Context {
	w.waitMu.Lock()
	defer w.waitMu.Unlock()
	if w.waitCtx == nil {
		w.waitCtx, w.waitCancel = context.WithCancel(context.Background())
	}
	return w.waitCtx
}

func (w *vmmWorker) cancelWait() {
	if w == nil {
		return
	}
	w.waitMu.Lock()
	if w.waitCtx == nil {
		w.waitCtx, w.waitCancel = context.WithCancel(context.Background())
	}
	cancel := w.waitCancel
	w.waitMu.Unlock()
	cancel()
}

const workerTrafficSyncInterval = 2 * time.Second

func (w *vmmWorker) startTrafficSync(rec *netpol.TrafficRecorder) {
	w.startTrafficSyncEvery(rec, workerTrafficSyncInterval)
}

// startTrafficSyncEvery exists so the short-lived-worker regression can
// choose an interval that provably cannot tick during the test.
func (w *vmmWorker) startTrafficSyncEvery(rec *netpol.TrafficRecorder, interval time.Duration) {
	if w == nil || rec == nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	w.trafficRec = rec
	w.trafficCancel = cancel
	w.trafficDone = make(chan struct{})
	go syncWorkerTraffic(ctx, w, rec, interval, w.trafficDone)
}

func (w *vmmWorker) stopTrafficSync() {
	if w == nil {
		return
	}
	w.trafficStopOnce.Do(func() {
		if w.trafficCancel != nil {
			w.trafficCancel()
		}
		if w.trafficDone != nil {
			<-w.trafficDone
		}
	})
}

func (w *vmmWorker) mergeFinalTraffic(snapshot *netpol.TrafficSnapshot) {
	w.stopTrafficSync()
	if w != nil && w.trafficRec != nil && snapshot != nil {
		w.trafficRec.SyncSnapshot(*snapshot)
	}
}

// startShareBroker connects the worker's request-only virtio-fs proxy to
// the supervisor-owned hub. The hub remains the sole owner of host paths,
// pinned directory descriptors, and Windows directory handles.
func (w *vmmWorker) startShareBroker(hub *virtio.ShareHub) error {
	if w == nil || w.share == nil {
		return fmt.Errorf("share relay unavailable")
	}
	if hub == nil {
		return fmt.Errorf("share hub unavailable")
	}
	if w.shareE != nil {
		return fmt.Errorf("share broker already started")
	}
	if w.stopping == nil {
		w.stopping = make(chan struct{})
	}
	w.shareE = make(chan error, 1)
	go func() {
		err := hub.ServeBroker(w.share)
		select {
		case <-w.stopping:
			return
		case <-w.dead:
			return
		default:
		}
		if err == nil {
			err = fmt.Errorf("share broker: share relay closed unexpectedly")
		}
		w.shareE <- err
		// FUSE operations are stateful and may mutate the host. Never
		// reconnect or replay after a truncated/malformed exchange.
		_ = w.Close()
	}()
	return nil
}

// Wait parks until the guest exits (the split-mode guestErr).
func (w *vmmWorker) Wait() error {
	ctx := w.waitContext()
	var out vmWaitResponse
	if err := w.client.CallContext(ctx, "vm.wait", nil, &out); err != nil {
		if errors.Is(err, context.Canceled) {
			// An unexpected share-relay failure initiates Close. Prefer its
			// actionable cause over the lifecycle cancellation it triggered.
			select {
			case shareErr := <-w.shareE:
				if shareErr == nil {
					shareErr = fmt.Errorf("share broker: share relay closed unexpectedly")
				}
				return shareErr
			default:
			}
			// setDead publishes the process result and closes dead before it
			// cancels this call, so a death-triggered cancellation retains
			// the authoritative process error.
			select {
			case <-w.dead:
				return w.Err()
			default:
			}
		}
		return err
	}
	w.mergeFinalTraffic(out.Traffic)
	if out.Err != "" {
		return fmt.Errorf("%s", out.Err)
	}
	return nil
}

// Close asks the worker to flush devices and exit, escalating to SIGKILL.
// Idempotent: teardown paths may stack (explicit stop + defer).
func (w *vmmWorker) Close() error {
	w.closeOnce.Do(func() {
		// vm.wait is deliberately unbounded during normal operation. Stop
		// it synchronously before beginning the bounded shutdown RPC.
		w.cancelWait()
		w.markStopping()
		w.stopTrafficSync()
		if w.client != nil {
			var out vmCloseResponse
			if err := w.client.CallWithTimeout("vm.close", nil, &out, 15*time.Second); err == nil {
				w.mergeFinalTraffic(out.Traffic)
			}
			_ = w.client.Close()
		}
		if w.bridge != nil {
			_ = w.bridge.Close()
		}
		if w.fdChan != nil {
			_ = w.fdChan.Close()
		}
		if w.share != nil {
			_ = w.share.Close()
		}
		select {
		case <-w.dead:
			w.closeErr = w.Err()
		case <-time.After(5 * time.Second):
			if w.proc != nil {
				_ = w.proc.Kill()
			}
			<-w.dead
			w.closeErr = w.Err()
		}
	})
	return w.closeErr
}

// TrafficSnapshot pulls the worker's in-memory enforcement counters
// (local-netstack topology only).
func (w *vmmWorker) TrafficSnapshot() (netpol.TrafficSnapshot, error) {
	var snap netpol.TrafficSnapshot
	err := w.client.Call("traffic.snapshot", struct{}{}, &snap)
	return snap, err
}

func (w *vmmWorker) trafficSnapshotContext(ctx context.Context) (netpol.TrafficSnapshot, error) {
	var snap netpol.TrafficSnapshot
	err := w.client.CallContext(ctx, "traffic.snapshot", struct{}{}, &snap)
	return snap, err
}

// SetPolicy pushes a live egress-policy swap to the worker (local-
// netstack topology only; the split-net topology uses the net-worker's
// prepare/commit RPCs instead).
func (w *vmmWorker) SetPolicy(policy *netpol.Policy) error {
	raw, err := netpol.Marshal(policy)
	if err != nil {
		return err
	}
	return w.client.Call("net.policy", netPolicyRequest{Policy: raw}, nil)
}

// ConfinementReport returns the worker's confinement report as carried
// by the boot ack (platform-neutral via a method so shared files never
// name the unix-only concrete type in field positions).
func (w *vmmWorker) ConfinementReport() workerconf.Report { return w.confReport }

// sendFD serializes a token-correlated descriptor transfer.
func (w *vmmWorker) sendFD(token [workerproto.FDTokenLen]byte, f *os.File) error {
	w.fdSend.Lock()
	defer w.fdSend.Unlock()
	return workerproto.SendFD(w.fdChan, token, f)
}

// DialStream opens a host->guest stream to the guest's listening port:
// a fresh socketpair, one end transferred to the worker, the other
// returned for the broker's session protocol.
func (w *vmmWorker) DialStream(guestPort uint32) (net.Conn, error) {
	sup, wrk, err := socketpairConns()
	if err != nil {
		return nil, err
	}
	wrkFile, err := connFile(wrk)
	_ = wrk.Close()
	if err != nil {
		_ = sup.Close()
		return nil, err
	}
	var token [workerproto.FDTokenLen]byte
	if _, err := rand.Read(token[:]); err != nil {
		_ = sup.Close()
		_ = wrkFile.Close()
		return nil, err
	}
	// The descriptor goes first (the worker's handler blocks on Recv
	// before answering); a dead worker surfaces as a send error.
	if err := w.sendFD(token, wrkFile); err != nil {
		_ = sup.Close()
		_ = wrkFile.Close()
		return nil, fmt.Errorf("vsock.connect: %w", err)
	}
	_ = wrkFile.Close()
	err = w.client.Call("vsock.connect", vsockConnectRequest{Port: guestPort, Token: hex.EncodeToString(token[:])}, nil)
	if err != nil {
		_ = sup.Close()
		return nil, fmt.Errorf("vsock.connect: %w", err)
	}
	return sup, nil
}
