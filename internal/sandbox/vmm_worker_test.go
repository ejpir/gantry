//go:build linux || darwin

package sandbox

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/ejpir/gantry/internal/netpol"
	"github.com/ejpir/gantry/internal/virtio"
	"github.com/ejpir/gantry/internal/vmm"
	"github.com/ejpir/gantry/internal/workerconf"
	"github.com/ejpir/gantry/internal/workerproto"
)

// fakeVMM is a vmmRunnerImpl double: Run blocks until Close, Inject
// records the conn, and the captured Opts expose the worker's vsock
// dial func for bridge tests.
type fakeVMM struct {
	mu       sync.Mutex
	stop     chan struct{}
	stopOnce sync.Once
	injected []net.Conn
	opts     vmm.Opts
	runErr   error
	// Optional test gate: hold vm.close inside runner.Close so tests can
	// distinguish lifecycle cancellation from a normal vm.wait response.
	closeEntered chan<- struct{}
	closeRelease <-chan struct{}
}

func (f *fakeVMM) Run() error {
	<-f.stop
	return f.runErr
}

func (f *fakeVMM) Close() error {
	f.mu.Lock()
	entered, release := f.closeEntered, f.closeRelease
	f.mu.Unlock()
	if entered != nil {
		select {
		case entered <- struct{}{}:
		default:
		}
	}
	if release != nil {
		<-release
	}
	f.stopOnce.Do(func() { close(f.stop) })
	return nil
}

func (f *fakeVMM) setCloseGate(entered chan<- struct{}, release <-chan struct{}) {
	f.mu.Lock()
	f.closeEntered, f.closeRelease = entered, release
	f.mu.Unlock()
}

func (f *fakeVMM) InjectVsockConn(guestPort uint32, nc net.Conn) error {
	f.mu.Lock()
	f.injected = append(f.injected, nc)
	f.mu.Unlock()
	return nil
}

func (f *fakeVMM) lastInjected() net.Conn {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.injected) == 0 {
		return nil
	}
	return f.injected[len(f.injected)-1]
}

// installFakeBoot routes the worker's machine boot to a fake runner and
// returns it (after start) via the returned holder.
func installFakeBoot(t *testing.T) **fakeVMM {
	t.Helper()
	holder := new(*fakeVMM)
	old := vmmWorkerBoot
	vmmWorkerBoot = func(opts vmm.Opts) (vmmRunnerImpl, error) {
		f := &fakeVMM{stop: make(chan struct{}), opts: opts}
		*holder = f
		return f, nil
	}
	t.Cleanup(func() { vmmWorkerBoot = old })
	return holder
}

// vmmWorkerHarness drives runVMMWorker in-process: control/bridge and the
// request-only share relay on net.Pipe, the fd channel on a real socketpair
// (SCM_RIGHTS). It performs the supervisor-side handshake/nonces/ack and
// serves the bridge with a sandbox-dir forward handler.
type vmmWorkerHarness struct {
	w         *vmmWorker
	fake      **fakeVMM
	workerErr chan error
	dir       string
}

func startVMMWorkerHarness(t *testing.T, cfg vmmBootConfig, assets vmmWorkerTestAssets) *vmmWorkerHarness {
	t.Helper()
	holder := installFakeBoot(t)

	ctrlSup, ctrlWrk := net.Pipe()
	bridgeSup, bridgeWrk := net.Pipe()
	fdSup, fdWrk, err := socketpairConns()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	workerErr := make(chan error, 1)
	assetsFn := func(vmmBootConfig) (vmmWorkerAssets, error) { return assets.worker, nil }
	go func() { workerErr <- runVMMWorker(ctrlWrk, bridgeWrk, fdWrk, assetsFn) }()

	nonce := make([]byte, 32)
	if _, err := io.ReadFull(randReader{}, nonce); err != nil {
		t.Fatal(err)
	}
	if err := workerproto.SendHandshake(ctrlSup, workerproto.RoleVMM, nonce, cfg); err != nil {
		t.Fatal(err)
	}
	if err := workerproto.WriteNonce(fdSup, nonce); err != nil {
		t.Fatal(err)
	}
	if err := workerproto.WriteNonce(assets.shareSup, nonce); err != nil {
		t.Fatal(err)
	}
	var ack struct {
		OK          bool              `json:"ok"`
		Error       string            `json:"error"`
		Confinement workerconf.Report `json:"confinement"`
	}
	_ = ctrlSup.SetReadDeadline(time.Now().Add(15 * time.Second))
	if err := workerproto.ReadMessage(ctrlSup, &ack); err != nil {
		t.Fatalf("boot ack: %v", err)
	}
	_ = ctrlSup.SetReadDeadline(time.Time{})
	if !ack.OK {
		t.Fatalf("worker boot: %s", ack.Error)
	}

	w := &vmmWorker{
		client:     workerproto.NewClient(ctrlSup),
		fdChan:     fdSup,
		bridge:     bridgeSup,
		bridgeE:    make(chan error, 1),
		share:      assets.shareSup,
		stopping:   make(chan struct{}),
		dead:       make(chan struct{}),
		confReport: ack.Confinement,
	}
	go func() {
		w.bridgeE <- workerproto.ServeRequests(bridgeSup, map[string]workerproto.Handler{
			"vsock.forward": w.vsockForward(dir),
		})
	}()
	// In-process: no proc reaper; mark dead when the worker loop returns.
	go func() {
		err := <-workerErr
		workerErr <- err // replay for cleanup
		w.setDead(err)
	}()
	h := &vmmWorkerHarness{w: w, fake: holder, workerErr: workerErr, dir: dir}
	t.Cleanup(func() {
		_ = w.Close()
		select {
		case err := <-workerErr:
			if err != nil {
				t.Errorf("worker exited with error: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("worker did not exit after close")
		}
	})
	return h
}

func TestVMMWorkerBootTimingOrigin(t *testing.T) {
	origin := time.Unix(1234, 5678)
	h := startVMMWorkerHarness(t, vmmBootConfig{
		MemSize:                 1 << 20,
		BootTimingStartUnixNano: origin.UnixNano(),
	}, testAssets(t))

	if got := (*h.fake).opts.BootTimingStart; !got.Equal(origin) {
		t.Fatalf("worker boot timing origin = %s, want %s", got, origin)
	}
}

// TestVMMWorkerNetPolicyEnforcement is the regression for the split-VMM
// local-netstack policy drop: in the degraded topology (net-worker
// failed in auto, VMM split succeeded) the worker's virtio-net device is
// the ONLY egress enforcement point, so the policy must cross in the
// boot config and net.policy must swap it live — a nil policy on the
// device is allow-all, silently dropping every configured deny including
// the default local-network wall.
func TestVMMWorkerNetPolicyEnforcement(t *testing.T) {
	raw, err := netpol.Marshal(netpol.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	h := startVMMWorkerHarness(t, vmmBootConfig{
		MemSize: 1 << 20, Policy: raw,
	}, testAssets(t))

	fake := *h.fake
	if fake.opts.NetPolicy == nil {
		t.Fatal("worker booted without the local-netstack policy: device would be allow-all")
	}
	if fake.opts.NetTraffic == nil {
		t.Fatal("worker booted without the traffic recorder")
	}
	// Boot policy: internet reachable, LAN walled off (DefaultPolicy).
	if !fake.opts.NetPolicy.Allows([4]byte{8, 8, 8, 8}, 6, 443) {
		t.Fatal("boot policy denies plain internet egress; want DefaultPolicy semantics")
	}
	if fake.opts.NetPolicy.Allows([4]byte{192, 168, 1, 20}, 6, 443) {
		t.Fatal("boot policy allows the LAN; want the default local-network wall")
	}
	// A live swap via net.policy must reach the device's policy object.
	if err := h.w.SetPolicy(&netpol.Policy{DefaultAllow: true, AllowLocal: true}); err != nil {
		t.Fatalf("SetPolicy: %v", err)
	}
	if !fake.opts.NetPolicy.Allows([4]byte{192, 168, 1, 20}, 6, 443) {
		t.Fatal("net.policy swap did not reach the device's policy")
	}
	// Counters accumulate in the worker (no host paths under
	// confinement); the supervisor pulls them over traffic.snapshot and
	// merges into its own recorder.
	snap, err := h.w.TrafficSnapshot()
	if err != nil {
		t.Fatalf("TrafficSnapshot: %v", err)
	}
	sup := netpol.NewTrafficRecorder("")
	sup.SyncSnapshot(snap)
	if got := sup.Snapshot(); got.Version == 0 {
		t.Fatal("supervisor recorder did not merge the worker snapshot")
	}
}

// A VM may exit before the two-second periodic pull ever fires. Its vm.wait
// response must carry the worker's final counters while control is still
// alive; attempting the final pull from Done necessarily races a dead socket.
func TestVMMWorkerWaitFurnishesTrafficBeforeFirstPeriodicSync(t *testing.T) {
	raw, err := netpol.Marshal(netpol.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	h := startVMMWorkerHarness(t, vmmBootConfig{
		MemSize: 1 << 20,
		Policy:  raw,
	}, testAssets(t))

	supervisorTraffic := netpol.NewTrafficRecorder("")
	t.Cleanup(supervisorTraffic.Close)
	// An hour-long interval makes the lifecycle response, rather than a
	// scheduler-dependent periodic tick, the only possible source.
	h.w.startTrafficSyncEvery(supervisorTraffic, time.Hour)
	workerTraffic := (*h.fake).opts.NetTraffic
	workerTraffic.ObserveTX([]byte{1, 2, 3, 4, 5}, false)

	// Exit immediately, then issue the parked lifetime wait. vmErr is
	// buffered, so this also covers a worker that beats the wait request.
	if err := (*h.fake).Close(); err != nil {
		t.Fatal(err)
	}
	if err := h.w.Wait(); err != nil {
		t.Fatalf("vm.wait: %v", err)
	}
	got := supervisorTraffic.Snapshot()
	if got.TXBytes != 5 || got.TXPackets != 1 || got.DroppedBytes != 5 || got.DroppedPackets != 1 {
		t.Fatalf("final traffic = %+v, want one five-byte dropped TX packet", got)
	}
}

// Explicit shutdown uses vm.close rather than vm.wait. The close response
// must likewise carry counters collected after the runner has been stopped.
func TestVMMWorkerCloseFurnishesFinalTraffic(t *testing.T) {
	raw, err := netpol.Marshal(netpol.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	h := startVMMWorkerHarness(t, vmmBootConfig{
		MemSize: 1 << 20,
		Policy:  raw,
	}, testAssets(t))

	supervisorTraffic := netpol.NewTrafficRecorder("")
	t.Cleanup(supervisorTraffic.Close)
	h.w.startTrafficSyncEvery(supervisorTraffic, time.Hour)
	(*h.fake).opts.NetTraffic.ObserveTX([]byte{1, 2, 3}, true)

	if err := h.w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	got := supervisorTraffic.Snapshot()
	if got.TXBytes != 3 || got.TXPackets != 1 || got.DroppedPackets != 0 {
		t.Fatalf("final traffic = %+v, want one three-byte allowed TX packet", got)
	}
}

// TestVMMWorkerRejectsBadPolicy: an unparseable boot policy must fail
// the worker boot, never degrade into an allow-all device.
func TestVMMWorkerRejectsBadPolicy(t *testing.T) {
	ctrlSup, ctrlWrk := net.Pipe()
	defer func() { _ = ctrlSup.Close() }()
	bridgeSup, bridgeWrk := net.Pipe()
	defer func() { _ = bridgeSup.Close() }()
	fdSup, fdWrk, err := socketpairConns()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fdSup.Close() }()
	assets := testAssets(t)
	workerErr := make(chan error, 1)
	go func() {
		workerErr <- runVMMWorker(ctrlWrk, bridgeWrk, fdWrk, func(vmmBootConfig) (vmmWorkerAssets, error) {
			return assets.worker, nil
		})
	}()
	nonce := make([]byte, 32)
	if err := workerproto.SendHandshake(ctrlSup, workerproto.RoleVMM, nonce,
		vmmBootConfig{MemSize: 1 << 20, Policy: []byte("{not a policy")}); err != nil {
		t.Fatal(err)
	}
	if err := workerproto.WriteNonce(fdSup, nonce); err != nil {
		t.Fatal(err)
	}
	if err := workerproto.WriteNonce(assets.shareSup, nonce); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-workerErr:
		if err == nil || !strings.Contains(err.Error(), "network policy") {
			t.Fatalf("worker exited with %v, want a network-policy failure", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("worker did not reject the bad policy")
	}
}

// randReader avoids importing crypto/rand in two spots.
type randReader struct{}

func (randReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(i*31 + 7)
	}
	return len(p), nil
}

type vmmWorkerTestAssets struct {
	worker   vmmWorkerAssets
	shareSup net.Conn
}

// testAssets returns minimal live assets: net.Pipe ends for the worker's
// unused network link and request-only share relay, a console temp file,
// and a fake kernel. The supervisor share end carries the launch nonce and
// can later serve the trusted ShareHub in broker tests.
func testAssets(t *testing.T) vmmWorkerTestAssets {
	t.Helper()
	dev, _ := net.Pipe()
	t.Cleanup(func() { _ = dev.Close() })
	shareSup, shareWrk := net.Pipe()
	t.Cleanup(func() {
		_ = shareSup.Close()
		_ = shareWrk.Close()
	})
	console, err := os.CreateTemp(t.TempDir(), "console-*")
	if err != nil {
		t.Fatal(err)
	}
	kernel := filepath.Join(t.TempDir(), "Image")
	hdr := make([]byte, 64)
	copy(hdr[0x38:], "ARM\x64")
	if err := os.WriteFile(kernel, hdr, 0o600); err != nil {
		t.Fatal(err)
	}
	kf, err := os.Open(kernel)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = console.Close()
		_ = kf.Close()
	})
	return vmmWorkerTestAssets{
		worker:   vmmWorkerAssets{ShareConn: shareWrk, NetConn: dev, Console: console, Kernel: kf},
		shareSup: shareSup,
	}
}

// TestVMMWorkerLifecycle: handshake + boot ack + parked vm.wait, then
// vm.close flushes (fake Close) and unwinds the worker with exit 0.
func TestVMMWorkerLifecycle(t *testing.T) {
	h := startVMMWorkerHarness(t, vmmBootConfig{MemSize: 1 << 20}, testAssets(t))
	// Ordinary control operations stay bounded, but vm.wait represents the
	// VM lifetime and must not inherit that RPC deadline.
	h.w.client.Timeout = 5 * time.Millisecond

	waitOut := make(chan error, 1)
	go func() { waitOut <- h.w.Wait() }()
	select {
	case err := <-waitOut:
		t.Fatalf("vm.wait returned before VM exit: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	// Fake VM exit: Close unblocks Run -> vm.wait responds.
	if err := (*h.fake).Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-waitOut:
		if err != nil {
			t.Fatalf("vm.wait: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("vm.wait never responded after VM exit")
	}
	// Graceful stop: vm.close OK, then the worker unwinds.
	if err := h.w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

func TestVMMWorkerWaitCanceledByClose(t *testing.T) {
	h := startVMMWorkerHarness(t, vmmBootConfig{MemSize: 1 << 20}, testAssets(t))
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	(*h.fake).setCloseGate(entered, release)

	waitOut := make(chan error, 1)
	go func() { waitOut <- h.w.Wait() }()
	select {
	case err := <-waitOut:
		t.Fatalf("vm.wait returned before close: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	closeOut := make(chan error, 1)
	go func() { closeOut <- h.w.Close() }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("vm.close did not reach the fake runner")
	}
	// runner.Close is still gated, so vm.wait cannot have a guest-exit
	// response. Only explicit lifecycle cancellation can unblock it here.
	select {
	case err := <-waitOut:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("vm.wait after Close = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not cancel vm.wait")
	}
	releaseOnce.Do(func() { close(release) })
	select {
	case err := <-closeOut:
		if err != nil {
			t.Fatalf("close: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not finish after releasing the fake runner")
	}
}

func TestVMMWorkerWaitCanceledByProcessDeath(t *testing.T) {
	ctrlSup, ctrlWorker := net.Pipe()
	t.Cleanup(func() { _ = ctrlSup.Close(); _ = ctrlWorker.Close() })
	received := make(chan struct{})
	go func() {
		var req workerproto.Request
		_ = workerproto.ReadMessage(ctrlWorker, &req)
		close(received)
	}()
	w := &vmmWorker{
		client:   workerproto.NewClient(ctrlSup),
		stopping: make(chan struct{}),
		dead:     make(chan struct{}),
	}
	waitOut := make(chan error, 1)
	go func() { waitOut <- w.Wait() }()
	select {
	case <-received:
	case <-time.After(time.Second):
		t.Fatal("vm.wait did not reach the worker")
	}
	want := errors.New("worker reaped after signal")
	w.setDead(want)
	select {
	case err := <-waitOut:
		if !errors.Is(err, want) {
			t.Fatalf("vm.wait after process death = %v, want %v", err, want)
		}
	case <-time.After(time.Second):
		t.Fatal("process death did not cancel vm.wait")
	}
}

func TestVMMWorkerShareBrokerExitStopsWorker(t *testing.T) {
	h := startVMMWorkerHarness(t, vmmBootConfig{MemSize: 1 << 20}, testAssets(t))
	hub, err := virtio.NewShareHub()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hub.Close() }()
	if err := h.w.startShareBroker(hub); err != nil {
		t.Fatal(err)
	}

	// Closing the worker frontend while the worker is otherwise healthy is
	// an unexpected relay exit. The supervisor must tear the worker down;
	// reconnecting could replay a stateful host mutation.
	if err := (*h.fake).opts.ShareProxy.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-h.w.shareE:
		if err == nil || !strings.Contains(err.Error(), "closed unexpectedly") {
			t.Fatalf("share broker exit = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("share broker did not report the closed relay")
	}
	select {
	case <-h.w.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("share broker exit did not stop the VMM worker")
	}
}

func TestVMMWorkerNormalCloseDoesNotReportBrokerFailure(t *testing.T) {
	h := startVMMWorkerHarness(t, vmmBootConfig{MemSize: 1 << 20}, testAssets(t))
	hub, err := virtio.NewShareHub()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hub.Close() }()
	if err := h.w.startShareBroker(hub); err != nil {
		t.Fatal(err)
	}

	if err := h.w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	select {
	case err := <-h.w.shareE:
		t.Fatalf("normal close reported broker failure: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
}

// TestVMMWorkerBootFailure: a failed Prepare surfaces as ack{ok:false}.
func TestVMMWorkerBootFailure(t *testing.T) {
	old := vmmWorkerBoot
	vmmWorkerBoot = func(vmm.Opts) (vmmRunnerImpl, error) { return nil, fmt.Errorf("no /dev/kvm") }
	t.Cleanup(func() { vmmWorkerBoot = old })

	ctrlSup, ctrlWrk := net.Pipe()
	defer func() { _ = ctrlSup.Close() }()
	bridgeSup, bridgeWrk := net.Pipe()
	defer func() { _ = bridgeSup.Close() }()
	fdSup, fdWrk, err := socketpairConns()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fdSup.Close() }()
	assets := testAssets(t)
	workerErr := make(chan error, 1)
	go func() {
		workerErr <- runVMMWorker(ctrlWrk, bridgeWrk, fdWrk, func(vmmBootConfig) (vmmWorkerAssets, error) {
			return assets.worker, nil
		})
	}()
	nonce := make([]byte, 32)
	if err := workerproto.SendHandshake(ctrlSup, workerproto.RoleVMM, nonce, vmmBootConfig{}); err != nil {
		t.Fatal(err)
	}
	if err := workerproto.WriteNonce(fdSup, nonce); err != nil {
		t.Fatal(err)
	}
	if err := workerproto.WriteNonce(assets.shareSup, nonce); err != nil {
		t.Fatal(err)
	}
	var ack struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := workerproto.ReadMessage(ctrlSup, &ack); err != nil {
		t.Fatal(err)
	}
	if ack.OK || ack.Error == "" {
		t.Fatalf("boot failure reported as %+v", ack)
	}
	if err := <-workerErr; err == nil {
		t.Fatal("worker returned nil after boot failure")
	}
}

// TestVMMWorkerVsockConnect: a host->guest stream crosses as a
// descriptor and lands in the device's injected conn.
func TestVMMWorkerVsockConnect(t *testing.T) {
	h := startVMMWorkerHarness(t, vmmBootConfig{}, testAssets(t))

	conn, err := h.w.DialStream(1026)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	deadline := time.Now().Add(5 * time.Second)
	for (*h.fake).lastInjected() == nil {
		if time.Now().After(deadline) {
			t.Fatal("no injected conn")
		}
		time.Sleep(5 * time.Millisecond)
	}
	injected := (*h.fake).lastInjected()
	if _, err := conn.Write([]byte("session-bytes")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 32)
	_ = injected.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := injected.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "session-bytes" {
		t.Fatalf("injected conn read %q", buf[:n])
	}
}

// TestVMMWorkerVsockForward: a guest->host dial-back is brokered by the
// supervisor: the worker's dial func crosses the bridge and returns a
// live conn to the sandbox-dir listener.
func TestVMMWorkerVsockForward(t *testing.T) {
	h := startVMMWorkerHarness(t, vmmBootConfig{}, testAssets(t))

	// The broker's API listener (supervisor-owned host socket).
	ln, err := net.Listen("unix", filepath.Join(h.dir, "1025.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		buf := make([]byte, 64)
		n, _ := c.Read(buf)
		_, _ = c.Write(buf[:n]) // echo
	}()

	dial := (*h.fake).opts.VsockDial
	if dial == nil {
		t.Fatal("worker opts lack the bridged vsock dial func")
	}
	conn, err := dial(1025)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write([]byte("dial-back")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "dial-back" {
		t.Fatalf("echo read %q", buf[:n])
	}
	// And no host->guest unix listeners exist in the worker topology.
	if !(*h.fake).opts.VsockNoListen {
		t.Fatal("VsockNoListen not set in worker opts")
	}
}

// TestVMMWorkerNonceMismatchRefused: a cross-wired fd channel dies at
// the nonce check, before any RPC or frame.
func TestVMMWorkerNonceMismatchRefused(t *testing.T) {
	installFakeBoot(t)
	ctrlSup, ctrlWrk := net.Pipe()
	defer func() { _ = ctrlSup.Close() }()
	bridgeSup, bridgeWrk := net.Pipe()
	defer func() { _ = bridgeSup.Close() }()
	fdSup, fdWrk, err := socketpairConns()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fdSup.Close() }()
	assets := testAssets(t)
	workerErr := make(chan error, 1)
	go func() {
		workerErr <- runVMMWorker(ctrlWrk, bridgeWrk, fdWrk, func(vmmBootConfig) (vmmWorkerAssets, error) {
			return assets.worker, nil
		})
	}()
	nonce := make([]byte, 32)
	if err := workerproto.SendHandshake(ctrlSup, workerproto.RoleVMM, nonce, vmmBootConfig{}); err != nil {
		t.Fatal(err)
	}
	wrong := make([]byte, 32)
	wrong[0] = 0xff
	if err := workerproto.WriteNonce(fdSup, wrong); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-workerErr:
		if err == nil {
			t.Fatal("worker accepted a mismatched nonce")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not reject the nonce mismatch")
	}
}

func TestVMMWorkerShareNonceMismatchRefused(t *testing.T) {
	installFakeBoot(t)
	ctrlSup, ctrlWrk := net.Pipe()
	defer func() { _ = ctrlSup.Close() }()
	bridgeSup, bridgeWrk := net.Pipe()
	defer func() { _ = bridgeSup.Close() }()
	fdSup, fdWrk, err := socketpairConns()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fdSup.Close() }()
	assets := testAssets(t)
	workerErr := make(chan error, 1)
	go func() {
		workerErr <- runVMMWorker(ctrlWrk, bridgeWrk, fdWrk, func(vmmBootConfig) (vmmWorkerAssets, error) {
			return assets.worker, nil
		})
	}()
	nonce := make([]byte, 32)
	if err := workerproto.SendHandshake(ctrlSup, workerproto.RoleVMM, nonce, vmmBootConfig{}); err != nil {
		t.Fatal(err)
	}
	if err := workerproto.WriteNonce(fdSup, nonce); err != nil {
		t.Fatal(err)
	}
	wrong := append([]byte(nil), nonce...)
	wrong[0] ^= 0xff
	if err := workerproto.WriteNonce(assets.shareSup, wrong); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-workerErr:
		if err == nil || !strings.Contains(err.Error(), "share channel nonce") {
			t.Fatalf("worker accepted mismatched share nonce: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not reject the share nonce mismatch")
	}
}

// TestVMMWorkerHelperProcess is the re-exec'd child (see
// TestVMMWorkerReExec): fake boot + real CmdVMMWorker entry point.
func TestVMMWorkerHelperProcess(t *testing.T) {
	if os.Getenv("GANTRY_TEST_VMM_WORKER") != "1" {
		return
	}
	vmmWorkerBoot = func(opts vmm.Opts) (vmmRunnerImpl, error) {
		return &fakeVMM{stop: make(chan struct{}), opts: opts}, nil
	}
	os.Exit(CmdVMMWorker())
}

func TestVMMWorkerEarlyExitHelper(t *testing.T) {
	if os.Getenv("GANTRY_TEST_VMM_WORKER_EARLY_EXIT") != "1" {
		return
	}
	os.Exit(9)
}

// TestVMMWorkerSpawnFailurePreservesNetConn protects auto-mode fallback:
// none of the caller's boot assets may be consumed until the child has sent
// a successful boot ack.
func TestVMMWorkerSpawnFailurePreservesNetConn(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	old := vmmWorkerSpawnHook
	vmmWorkerSpawnHook = func(argv *[]string, env *[]string) {
		*argv = []string{exe, "-test.run", "^TestVMMWorkerEarlyExitHelper$"}
		*env = append(*env, "GANTRY_TEST_VMM_WORKER_EARLY_EXIT=1")
	}
	t.Cleanup(func() { vmmWorkerSpawnHook = old })

	netSup, netDev, err := socketpairConns()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = netSup.Close() }()
	defer func() { _ = netDev.Close() }()
	console, err := os.CreateTemp(t.TempDir(), "console-*")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = console.Close() }()
	kernelPath := filepath.Join(t.TempDir(), "Image")
	hdr := make([]byte, 64)
	copy(hdr[0x38:], "ARM\x64")
	if err := os.WriteFile(kernelPath, hdr, 0o600); err != nil {
		t.Fatal(err)
	}
	kernel, err := os.Open(kernelPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = kernel.Close() }()

	if _, err := spawnVMMWorker(vmmBootConfig{MemSize: 1 << 20}, vmmWorkerAssets{
		NetConn: netDev, Console: console, Kernel: kernel,
	}, t.TempDir()); err == nil {
		t.Fatal("early worker exit unexpectedly booted")
	}
	if err := netDev.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := netDev.Write([]byte("fallback")); err != nil {
		t.Fatalf("failed spawn consumed fallback net connection: %v", err)
	}
	buf := make([]byte, len("fallback"))
	if err := netSup.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(netSup, buf); err != nil || string(buf) != "fallback" {
		t.Fatalf("fallback net connection read %q, %v", buf, err)
	}
	// The child and the spawn path must also have released every duplicate.
	// Once the caller closes its still-owned endpoint, the peer must observe
	// EOF; a leaked netFile/child descriptor would keep the socket alive.
	if err := netDev.Close(); err != nil {
		t.Fatal(err)
	}
	if err := netSup.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	var one [1]byte
	if n, err := netSup.Read(one[:]); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("failed spawn leaked a network duplicate: read %d, err %v", n, err)
	}
}

func TestNamespaceUnavailableClassification(t *testing.T) {
	for _, errno := range []error{syscall.EPERM, syscall.EACCES, syscall.ENOSPC, syscall.EUSERS} {
		if !isNamespaceUnavailable(&os.PathError{Op: "fork/exec", Path: "worker", Err: errno}) {
			t.Errorf("%v was not classified as namespace-unavailable", errno)
		}
	}
	for _, err := range []error{syscall.EINVAL, syscall.ENOENT, errors.New("boom")} {
		if isNamespaceUnavailable(err) {
			t.Errorf("%v was classified as namespace-unavailable", err)
		}
	}
}

// TestVMMWorkerReExec spawns the real _vmm-worker (helper-process
// pattern): descriptor table, handshake, nonce, ack, vm.wait, and the
// vm.close shutdown over inherited channels.
func TestVMMWorkerReExec(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	old := vmmWorkerSpawnHook
	vmmWorkerSpawnHook = func(argv *[]string, env *[]string) {
		*argv = []string{exe, "-test.run", "^TestVMMWorkerHelperProcess$"}
		*env = append(*env, "GANTRY_TEST_VMM_WORKER=1")
	}
	t.Cleanup(func() { vmmWorkerSpawnHook = old })

	netSup, netDev, err := socketpairConns()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = netSup.Close() }()
	console, err := os.CreateTemp(t.TempDir(), "console-*")
	if err != nil {
		t.Fatal(err)
	}
	kernel := filepath.Join(t.TempDir(), "Image")
	hdr := make([]byte, 64)
	copy(hdr[0x38:], "ARM\x64")
	if err := os.WriteFile(kernel, hdr, 0o600); err != nil {
		t.Fatal(err)
	}
	kf, err := os.Open(kernel)
	if err != nil {
		t.Fatal(err)
	}

	vw, err := spawnVMMWorker(vmmBootConfig{MemSize: 1 << 20}, vmmWorkerAssets{
		NetConn: netDev, Console: console, Kernel: kf,
	}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// The successful boot ack is the ownership commit point: the original
	// supervisor endpoint is closed, while the descriptor inherited by the
	// worker remains connected to netSup.
	if _, err := netDev.Write([]byte("must-be-closed")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("successful spawn retained caller NetConn: %v", err)
	}
	if err := netSup.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := netSup.Write([]byte{1}); err != nil {
		t.Fatalf("worker did not retain transferred NetConn duplicate: %v", err)
	}
	// Parked wait, then graceful close -> worker exits 0.
	waitOut := make(chan error, 1)
	go func() { waitOut <- vw.Wait() }()
	select {
	case err := <-waitOut:
		t.Fatalf("vm.wait returned early: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if err := vw.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	// Wait reports the VM exit once the fake runner unwinds... the fake
	// Run returns on Close; vm.wait may already have raced the close.
	select {
	case <-vw.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("worker process did not exit")
	}
	if err := vw.Err(); err != nil {
		t.Fatalf("worker exit: %v", err)
	}
}

func TestVMMKeepFDs(t *testing.T) {
	base := vmmKeepFDs(vmmBootConfig{})
	if base != 9 { // fds 0..8 fixed + kernel at 9
		t.Fatalf("base keepFDs: %d", base)
	}
	full := vmmKeepFDs(vmmBootConfig{HasRoot: true, NDisksRO: 2, NDisks: 1, HasKVM: true})
	if full != base+1+2+1+1 {
		t.Fatalf("full keepFDs: %d", full)
	}
}

// TestVMMWorkerConfinementReport: the worker applies confinement after
// the descriptor table is consumed, and the verified report rides the
// boot ack to the supervisor.
func TestVMMWorkerConfinementReport(t *testing.T) {
	oldA, oldV := workerconfApplyFn, workerconfVerifyFn
	t.Cleanup(func() { workerconfApplyFn, workerconfVerifyFn = oldA, oldV })
	var sawSpec workerconf.Spec
	workerconfApplyFn = func(spec workerconf.Spec) (*workerconf.Report, error) {
		sawSpec = spec
		rep := &workerconf.Report{Platform: "linux", Applied: true, Notes: []string{"fake tier"}}
		return rep, nil
	}
	workerconfVerifyFn = func(spec workerconf.Spec, rep *workerconf.Report) {
		rep.Results = []workerconf.PropertyResult{
			{Property: workerconf.PropFSRead, State: workerconf.StateEnforced, Detail: "fake"},
			{Property: workerconf.PropNetDial, State: workerconf.StateEnforced, Detail: "fake"},
			{Property: workerconf.PropExec, State: workerconf.StateEnforced, Detail: "fake"},
		}
	}
	cfg := vmmBootConfig{MemSize: 1 << 20, Confinement: "auto", ConfRoot: t.TempDir()}
	h := startVMMWorkerHarness(t, cfg, testAssets(t))
	if sawSpec.ConfRoot == "" {
		t.Fatal("worker did not receive the confinement spec")
	}
	if sawSpec.KeepFDs != vmmKeepFDs(cfg) {
		t.Fatalf("spec KeepFDs %d, want %d", sawSpec.KeepFDs, vmmKeepFDs(cfg))
	}
	rep := h.w.ConfinementReport()
	if !rep.Applied || rep.Mode != "auto" {
		t.Fatalf("supervisor-side report: %+v", rep)
	}
	if rep.Property(workerconf.PropNetDial).State != workerconf.StateEnforced {
		t.Fatalf("report lost verify results: %+v", rep)
	}
}

// TestVMMWorkerConfinementRequiredRefused: required mode fails the boot
// (with a structured error ack) when cross-process isolation is not
// enforced, even if every filesystem/network/exec property is.
func TestVMMWorkerConfinementRequiredRefused(t *testing.T) {
	oldA, oldV := workerconfApplyFn, workerconfVerifyFn
	t.Cleanup(func() { workerconfApplyFn, workerconfVerifyFn = oldA, oldV })
	workerconfApplyFn = func(workerconf.Spec) (*workerconf.Report, error) {
		return &workerconf.Report{Platform: "linux", Applied: true}, nil
	}
	workerconfVerifyFn = func(_ workerconf.Spec, rep *workerconf.Report) {
		rep.Results = []workerconf.PropertyResult{
			{Property: workerconf.PropFSRead, State: workerconf.StateEnforced},
			{Property: workerconf.PropFSWrite, State: workerconf.StateEnforced},
			{Property: workerconf.PropNetDial, State: workerconf.StateEnforced},
			{Property: workerconf.PropExec, State: workerconf.StateEnforced},
			{Property: workerconf.PropProcEnum, State: workerconf.StateUnenforced, Detail: "/proc readable"},
		}
	}
	ctrlSup, ctrlWrk := net.Pipe()
	defer func() { _ = ctrlSup.Close() }()
	bridgeSup, bridgeWrk := net.Pipe()
	defer func() { _ = bridgeSup.Close() }()
	fdSup, fdWrk, err := socketpairConns()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fdSup.Close() }()
	assets := testAssets(t)
	workerErr := make(chan error, 1)
	go func() {
		workerErr <- runVMMWorker(ctrlWrk, bridgeWrk, fdWrk, func(vmmBootConfig) (vmmWorkerAssets, error) {
			return assets.worker, nil
		})
	}()
	nonce := make([]byte, 32)
	if err := workerproto.SendHandshake(ctrlSup, workerproto.RoleVMM, nonce,
		vmmBootConfig{MemSize: 1 << 20, Confinement: "required", ConfRoot: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	if err := workerproto.WriteNonce(fdSup, nonce); err != nil {
		t.Fatal(err)
	}
	if err := workerproto.WriteNonce(assets.shareSup, nonce); err != nil {
		t.Fatal(err)
	}
	var ack struct {
		OK          bool              `json:"ok"`
		Error       string            `json:"error"`
		Confinement workerconf.Report `json:"confinement"`
	}
	_ = ctrlSup.SetReadDeadline(time.Now().Add(15 * time.Second))
	if err := workerproto.ReadMessage(ctrlSup, &ack); err != nil {
		t.Fatalf("refusal ack: %v", err)
	}
	if ack.OK || !strings.Contains(ack.Error, "required") || !strings.Contains(ack.Error, workerconf.PropProcEnum) {
		t.Fatalf("ack: %+v", ack)
	}
	if ack.Confinement.Property(workerconf.PropProcEnum).State != workerconf.StateUnenforced {
		t.Fatalf("refusal ack lost the report: %+v", ack.Confinement)
	}
	select {
	case err := <-workerErr:
		if err == nil || !strings.Contains(err.Error(), "required") {
			t.Fatalf("worker exited %v, want a required-confinement refusal", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("worker did not refuse the boot")
	}
}

func TestRequiredWorkerConfinementPropertiesArePlatformVerified(t *testing.T) {
	has := func(items []string, want string) bool {
		for _, item := range items {
			if item == want {
				return true
			}
		}
		return false
	}
	linux := requiredWorkerConfinementProperties("linux")
	if !has(linux, workerconf.PropProcEnum) || has(linux, workerconf.PropProcSignal) {
		t.Fatalf("Linux required properties = %v", linux)
	}
	darwin := requiredWorkerConfinementProperties("darwin")
	if !has(darwin, workerconf.PropProcSignal) || has(darwin, workerconf.PropProcEnum) {
		t.Fatalf("Darwin required properties = %v", darwin)
	}
}

// TestVMMWorkerDarwinConfinementBrokersLiveShares pins the Darwin wiring
// contract with a fake confinement report: the worker profile receives no
// host-share paths while the supervisor retains the live hub and proxy relay.
// Native Seatbelt enforcement is covered only by the macOS integration run.
func TestVMMWorkerDarwinConfinementBrokersLiveShares(t *testing.T) {
	manager, _ := newTestShareManager(t) // zero boot shares, RW

	oldA, oldV := workerconfApplyFn, workerconfVerifyFn
	t.Cleanup(func() { workerconfApplyFn, workerconfVerifyFn = oldA, oldV })
	var sawSpec workerconf.Spec
	workerconfApplyFn = func(spec workerconf.Spec) (*workerconf.Report, error) {
		sawSpec = spec
		return &workerconf.Report{Platform: "darwin", Applied: true}, nil
	}
	workerconfVerifyFn = func(workerconf.Spec, *workerconf.Report) {}
	h := startVMMWorkerHarness(t, vmmBootConfig{MemSize: 1 << 20, Confinement: "auto"}, testAssets(t))

	if len(sawSpec.FileAllow) != 0 {
		t.Fatalf("worker Seatbelt spec exposes host share paths: %+v", sawSpec.FileAllow)
	}
	if (*h.fake).opts.ShareProxy == nil || (*h.fake).opts.ShareHub != nil {
		t.Fatalf("worker share topology: proxy=%v hub=%v", (*h.fake).opts.ShareProxy, (*h.fake).opts.ShareHub)
	}
	if err := h.w.startShareBroker(manager.Hub()); err != nil {
		t.Fatalf("start share broker: %v", err)
	}

	root := t.TempDir()
	entry, err := manager.Add("docs="+root+",ro", false, false)
	if err != nil {
		t.Fatalf("local ShareManager hot-add: %v", err)
	}
	if entry.State != "active" || !entry.RO || entry.CtrPath != "/host/docs" {
		t.Fatalf("entry: %+v", entry)
	}
	exp := manager.Hub().Export("docs")
	if exp == nil || exp.Tag != "docs" || !exp.RO || exp.State().String() != "active" {
		t.Fatalf("supervisor hub export: %+v", exp)
	}
	if _, err := manager.Remove("docs", false, true); err != nil {
		t.Fatalf("local ShareManager remove: %v", err)
	}
}
