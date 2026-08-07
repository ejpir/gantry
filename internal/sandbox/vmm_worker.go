//go:build linux || darwin

package sandbox

// Phase 2a-iii of docs/vmm-network-isolation.md: the _vmm-worker process.
// The hypervisor, guest RAM, all virtio devices, disk image I/O, share
// serving, and the vsock data plane move out of the supervisor into a
// re-executed worker. The supervisor keeps ctl.sock, CLI sessions, the
// config store, network policy, and all host sockets.
//
// Channels (fixed descriptor slots, socketpairs):
//
//	fd 3  control — supervisor -> worker RPC (workerproto):
//	      vm.wait, vm.close, vsock.connect, share.*, shutdown
//	fd 4  bridge — worker -> supervisor RPC: vsock.forward (guest
//	      dial-back needs a supervisor-owned host socket)
//	fd 5  fd channel — SCM_RIGHTS transfers, ALL supervisor -> worker,
//	      token-correlated with RPCs on either RPC channel; the first
//	      32 bytes are the launch nonce (cross-wiring check)
//	fd 6  net data — QEMU-framed Ethernet to the net-worker (or the
//	      supervisor's in-process netstack in the degraded topology)
//	fd 7  console log (append-only)
//	fd 8+ kernel, rootfs?, DisksRO..., Disks..., share roots...
//
// The worker owns no host paths: boot assets arrive as descriptors,
// vsock dial-backs are brokered by the supervisor, host->guest streams
// arrive as descriptors. This is what Phase 2b confinement builds on.

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/ejpir/gantry/internal/virtio"
	"github.com/ejpir/gantry/internal/vmm"
	"github.com/ejpir/gantry/internal/workerproto"
)

// vmmBootConfig travels in the workerproto handshake. Counts define the
// descriptor table layout after the fixed slots.
type vmmBootConfig struct {
	MemSize  uint64         `json:"memSize"`
	VCPUs    int            `json:"vcpus"`
	Cmdline  string         `json:"cmdline"`
	NetMAC   [6]byte        `json:"netMAC"`
	GuestCID uint64         `json:"guestCID"`
	HasRoot  bool           `json:"hasRootfs"`
	NDisksRO int            `json:"nDisksRO"`
	NDisks   int            `json:"nDisks"`
	Shares   []vmmShareMeta `json:"shares"`
}

// vmmShareMeta is one hub export minus its root descriptor (which travels
// in the descriptor table, in the same order).
type vmmShareMeta struct {
	Tag  string  `json:"tag"`
	Path string  `json:"path"` // display/logging only — never opened by the worker
	RO   bool    `json:"ro"`
	UID  *uint32 `json:"uid,omitempty"`
	GID  *uint32 `json:"gid,omitempty"`
}

// vmmWorkerAssets are the already-open descriptors of the descriptor
// table (fd 6 onward), opened by the spawn code or the test harness.
type vmmWorkerAssets struct {
	NetConn    net.Conn
	Console    *os.File
	Kernel     *os.File
	Rootfs     *os.File
	DisksRO    []*os.File
	Disks      []*os.File
	ShareRoots []*os.File // len == len(cfg.Shares)
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
	if assets.NetConn != nil {
		defer func() { _ = assets.NetConn.Close() }()
	}
	// The fd channel's first bytes are the launch nonce: cross-wired
	// descriptor tables die here, before any RPC or frame.
	if err := workerproto.ReadNonce(fdChan, nonce); err != nil {
		return fmt.Errorf("fd channel nonce: %w", err)
	}
	fds := workerproto.NewFDMux(fdChan)
	bridgeClient := workerproto.NewClient(bridge)
	defer func() { _ = bridgeClient.Close() }()

	// The share hub ALWAYS lives in the worker (even with zero boot
	// exports, so post-boot hot-add works); the supervisor's ShareManager
	// drives it over share.* RPCs. Boot exports arrive as descriptors.
	hub, err := virtio.NewShareHub()
	if err != nil {
		return fmt.Errorf("share hub: %w", err)
	}
	if len(assets.ShareRoots) != len(cfg.Shares) {
		_ = hub.Close()
		return fmt.Errorf("descriptor table: %d share roots for %d shares", len(assets.ShareRoots), len(cfg.Shares))
	}
	for i, sh := range cfg.Shares {
		prepared, _, err := hub.PrepareMappedFD(sh.Tag, sh.Path, sh.RO, sh.UID, sh.GID, assets.ShareRoots[i])
		if err != nil {
			_ = hub.Close()
			return fmt.Errorf("share %s: %w", sh.Tag, err)
		}
		if _, err := hub.Publish(prepared); err != nil {
			_ = hub.Close()
			return fmt.Errorf("share %s: %w", sh.Tag, err)
		}
	}

	opts := vmm.Opts{
		MemSize:   cfg.MemSize,
		Kernel:    assets.Kernel,
		Rootfs:    assets.Rootfs,
		DisksRO:   assets.DisksRO,
		Disks:     assets.Disks,
		ShareHub:  hub,
		NetConn:   assets.NetConn,
		NetMAC:    cfg.NetMAC,
		GuestCID:  cfg.GuestCID,
		VCPUs:     cfg.VCPUs,
		Cmdline:   cfg.Cmdline,
		Console:   assets.Console,
		VsockDial: func(port uint32) (net.Conn, error) { return vsockForwardDial(bridgeClient, fds, port) },
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
	if err := workerproto.WriteMessage(control, map[string]any{"ok": true}); err != nil {
		return fmt.Errorf("boot ack: %w", err)
	}
	state := &vmmWorkerState{runner: runner, hub: hub, fds: fds, pending: map[string]*virtio.PreparedShare{}}
	vmErr := make(chan error, 1)
	go func() { vmErr <- runner.Run() }()
	state.vmErr = vmErr

	return workerproto.ServeRequests(control, map[string]workerproto.Handler{
		"vm.wait":       state.vmWait,
		"vm.close":      state.vmClose,
		"vsock.connect": state.vsockConnect,
		"share.prepare": state.sharePrepare,
		"share.publish": state.sharePublish,
		"share.swap":    state.shareSwap,
		"share.remove":  state.shareRemove,
		"share.drop":    state.shareDrop,
		"shutdown":      func(workerproto.Request) (any, error) { return nil, workerproto.ErrShutdown },
	})
}

// vmmWorkerState is the worker's mutable serving state. Prepare/publish
// tokens let the supervisor stage a share atomically (prepare + FD, then
// publish or drop) exactly as the local hub does.
type vmmWorkerState struct {
	runner  vmmRunnerImpl
	hub     *virtio.ShareHub
	fds     *workerproto.FDMux
	vmErr   chan error
	mu      sync.Mutex
	pending map[string]*virtio.PreparedShare
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
	return vmWaitResponse{Err: errString(err)}, nil
}

type vmWaitResponse struct {
	Err string `json:"err,omitempty"`
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// vmClose flushes devices (the review-finding-5 graceful stop) and then
// unwinds the worker: OK response, serve loop stops, process exits.
func (s *vmmWorkerState) vmClose(workerproto.Request) (any, error) {
	if err := s.runner.Close(); err != nil {
		return nil, err
	}
	return nil, workerproto.ErrShutdown
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

type sharePrepareRequest struct {
	Tag   string  `json:"tag"`
	Path  string  `json:"path"`
	RO    bool    `json:"ro"`
	UID   *uint32 `json:"uid,omitempty"`
	GID   *uint32 `json:"gid,omitempty"`
	Token string  `json:"token"`
}

type shareTokenRequest struct {
	Token string `json:"token"`
}

type shareRemoveRequest struct {
	Tag   string `json:"tag"`
	Force bool   `json:"force"`
}

// sharePrepare receives a pinned root descriptor and stages the export;
// the prepared token is parked until share.publish/swap or a drop.
func (s *vmmWorkerState) sharePrepare(req workerproto.Request) (any, error) {
	if s.hub == nil {
		return nil, fmt.Errorf("share hub unavailable")
	}
	var body sharePrepareRequest
	if err := json.Unmarshal(req.Body, &body); err != nil {
		return nil, fmt.Errorf("share.prepare: %w", err)
	}
	token, err := hex.DecodeString(body.Token)
	if err != nil || len(token) != workerproto.FDTokenLen {
		return nil, fmt.Errorf("share.prepare: bad token")
	}
	var tok [workerproto.FDTokenLen]byte
	copy(tok[:], token)
	f, err := s.fds.Recv(tok)
	if err != nil {
		return nil, fmt.Errorf("share.prepare: %w", err)
	}
	prepared, finalPath, err := s.hub.PrepareMappedFD(body.Tag, body.Path, body.RO, body.UID, body.GID, f)
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("share.prepare: %w", err)
	}
	s.mu.Lock()
	if s.pending == nil {
		s.pending = map[string]*virtio.PreparedShare{}
	}
	if s.pending[body.Token] != nil {
		s.mu.Unlock()
		prepared.ClosePrepared()
		return nil, fmt.Errorf("share.prepare: duplicate token")
	}
	s.pending[body.Token] = prepared
	s.mu.Unlock()
	return sharePrepareResponse{FinalPath: finalPath}, nil
}

type sharePrepareResponse struct {
	FinalPath string `json:"finalPath"`
}

// dropPrepared unparks and releases a staged share (rollback path).
func (s *vmmWorkerState) dropPrepared(token string) *virtio.PreparedShare {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.pending[token]
	delete(s.pending, token)
	return p
}

func (s *vmmWorkerState) sharePublish(req workerproto.Request) (any, error) {
	var body shareTokenRequest
	if err := json.Unmarshal(req.Body, &body); err != nil {
		return nil, fmt.Errorf("share.publish: %w", err)
	}
	p := s.dropPrepared(body.Token)
	if p == nil {
		return nil, fmt.Errorf("share.publish: unknown token")
	}
	exp, err := s.hub.Publish(p)
	if err != nil {
		p.ClosePrepared()
		return nil, fmt.Errorf("share.publish: %w", err)
	}
	return shareRecordResponse{Tag: exp.Tag, Path: exp.Path, RO: exp.RO}, nil
}

func (s *vmmWorkerState) shareSwap(req workerproto.Request) (any, error) {
	var body shareTokenRequest
	if err := json.Unmarshal(req.Body, &body); err != nil {
		return nil, fmt.Errorf("share.swap: %w", err)
	}
	p := s.dropPrepared(body.Token)
	if p == nil {
		return nil, fmt.Errorf("share.swap: unknown token")
	}
	_, exp, err := s.hub.Swap(p)
	if err != nil {
		p.ClosePrepared()
		return nil, fmt.Errorf("share.swap: %w", err)
	}
	return shareRecordResponse{Tag: exp.Tag, Path: exp.Path, RO: exp.RO}, nil
}

func (s *vmmWorkerState) shareRemove(req workerproto.Request) (any, error) {
	var body shareRemoveRequest
	if err := json.Unmarshal(req.Body, &body); err != nil {
		return nil, fmt.Errorf("share.remove: %w", err)
	}
	exp, err := s.hub.Remove(body.Tag, body.Force)
	if err != nil {
		return nil, fmt.Errorf("share.remove: %w", err)
	}
	return shareRecordResponse{Tag: exp.Tag, Path: exp.Path, RO: exp.RO}, nil
}

type shareRecordResponse struct {
	Tag  string `json:"tag"`
	Path string `json:"path"`
	RO   bool   `json:"ro"`
}

// shareDrop abandons a staged (prepared, never published) share — the
// ShareManager rollback path when persisting fails after prepare.
func (s *vmmWorkerState) shareDrop(req workerproto.Request) (any, error) {
	var body shareTokenRequest
	if err := json.Unmarshal(req.Body, &body); err != nil {
		return nil, fmt.Errorf("share.drop: %w", err)
	}
	if p := s.dropPrepared(body.Token); p != nil {
		p.ClosePrepared()
	}
	return nil, nil
}

// ------------------------------------------------------------ supervisor

// vmmWorker is the supervisor's handle on the worker process: control
// client, fd channel (send side), bridge serve loop, and lifecycle. It
// implements vmmRunner.
type vmmWorker struct {
	proc    *os.Process
	client  *workerproto.Client // control (fd 3)
	fdChan  net.Conn            // fd 5, send side
	fdSend  sync.Mutex          // serialize SCM_RIGHTS sends
	bridge  net.Conn
	bridgeE chan error

	dead    chan struct{} // closed when the process is reaped
	deadErr error
	deadMu  sync.RWMutex

	closeOnce sync.Once
	closeErr  error
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
	close(w.dead)
}

// Wait parks until the guest exits (the split-mode guestErr).
func (w *vmmWorker) Wait() error {
	var out vmWaitResponse
	if err := w.client.CallWithTimeout("vm.wait", nil, &out, 24*time.Hour); err != nil {
		return err
	}
	if out.Err != "" {
		return fmt.Errorf("%s", out.Err)
	}
	return nil
}

// Close asks the worker to flush devices and exit, escalating to SIGKILL.
// Idempotent: teardown paths may stack (explicit stop + defer).
func (w *vmmWorker) Close() error {
	w.closeOnce.Do(func() {
		if w.client != nil {
			_ = w.client.CallWithTimeout("vm.close", nil, nil, 15*time.Second)
			_ = w.client.Close()
		}
		_ = w.bridge.Close()
		_ = w.fdChan.Close()
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

// workerShareServing adapts ShareManager's hub operations to the
// worker-hosted hub. Tokens correlate the prepare/FD stage with the
// publish/swap commit.
type workerShareServing struct {
	w *vmmWorker
}

type workerPreparedShare struct {
	token string
}

func (s workerShareServing) PrepareMapped(tag, path string, ro bool, uid, gid *uint32) (any, string, error) {
	root, err := virtio.OpenShareRootFD(path)
	if err != nil {
		return nil, "", err
	}
	var token [workerproto.FDTokenLen]byte
	if _, err := rand.Read(token[:]); err != nil {
		_ = root.Close()
		return nil, "", err
	}
	tokenHex := hex.EncodeToString(token[:])
	if err := s.w.sendFD(token, root); err != nil {
		_ = root.Close()
		return nil, "", fmt.Errorf("share.prepare: %w", err)
	}
	_ = root.Close()
	var out sharePrepareResponse
	err = s.w.client.Call("share.prepare", sharePrepareRequest{
		Tag: tag, Path: path, RO: ro, UID: uid, GID: gid, Token: tokenHex,
	}, &out)
	if err != nil {
		return nil, "", err
	}
	return workerPreparedShare{token: tokenHex}, out.FinalPath, nil
}

func (s workerShareServing) Publish(p any) (*virtio.ShareExport, error) {
	prep, ok := p.(workerPreparedShare)
	if !ok {
		return nil, fmt.Errorf("bad prepared share token %T", p)
	}
	var out shareRecordResponse
	if err := s.w.client.Call("share.publish", shareTokenRequest{Token: prep.token}, &out); err != nil {
		return nil, err
	}
	return virtio.NewShareExportMirror(out.Tag, out.Path, out.RO, nil, nil, virtio.ShareExportActive), nil
}

func (s workerShareServing) Swap(p any) (old, exp *virtio.ShareExport, err error) {
	prep, ok := p.(workerPreparedShare)
	if !ok {
		return nil, nil, fmt.Errorf("bad prepared share token %T", p)
	}
	var out shareRecordResponse
	if err := s.w.client.Call("share.swap", shareTokenRequest{Token: prep.token}, &out); err != nil {
		return nil, nil, err
	}
	return nil, virtio.NewShareExportMirror(out.Tag, out.Path, out.RO, nil, nil, virtio.ShareExportActive), nil
}

func (s workerShareServing) Remove(tag string, force bool) (*virtio.ShareExport, error) {
	var out shareRecordResponse
	if err := s.w.client.Call("share.remove", shareRemoveRequest{Tag: tag, Force: force}, &out); err != nil {
		return nil, err
	}
	return virtio.NewShareExportMirror(out.Tag, out.Path, out.RO, nil, nil, virtio.ShareExportGone), nil
}

func (s workerShareServing) Close() error { return nil } // owned by vmmWorker.Close

// ClosePrepared abandons a staged share (ShareManager rollback path).
func (s workerShareServing) ClosePrepared(p any) {
	prep, ok := p.(workerPreparedShare)
	if !ok {
		return
	}
	// The worker drops the parked prepared share; best-effort.
	_ = s.w.client.Call("share.drop", shareTokenRequest{Token: prep.token}, nil)
}
