//go:build linux || darwin

package sandbox

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ejpir/gantry/internal/netpol"
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
}

func (f *fakeVMM) Run() error {
	<-f.stop
	return f.runErr
}

func (f *fakeVMM) Close() error {
	f.stopOnce.Do(func() { close(f.stop) })
	return nil
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

// vmmWorkerHarness drives runVMMWorker in-process: control/bridge on
// net.Pipe, the fd channel on a real socketpair (SCM_RIGHTS). It performs
// the supervisor-side handshake/nonce/ack and serves the bridge with a
// sandbox-dir forward handler.
type vmmWorkerHarness struct {
	w         *vmmWorker
	fake      **fakeVMM
	workerErr chan error
	dir       string
}

func startVMMWorkerHarness(t *testing.T, cfg vmmBootConfig, assets vmmWorkerAssets) *vmmWorkerHarness {
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
	assetsFn := func(vmmBootConfig) (vmmWorkerAssets, error) { return assets, nil }
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
	workerErr := make(chan error, 1)
	go func() {
		workerErr <- runVMMWorker(ctrlWrk, bridgeWrk, fdWrk, func(vmmBootConfig) (vmmWorkerAssets, error) {
			return testAssets(t), nil
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

// testAssets returns minimal live assets: a net.Pipe end (worker side is
// never read), a console temp file, and a fake kernel.
func testAssets(t *testing.T) vmmWorkerAssets {
	t.Helper()
	dev, _ := net.Pipe()
	t.Cleanup(func() { _ = dev.Close() })
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
	return vmmWorkerAssets{NetConn: dev, Console: console, Kernel: kf}
}

// TestVMMWorkerLifecycle: handshake + boot ack + parked vm.wait, then
// vm.close flushes (fake Close) and unwinds the worker with exit 0.
func TestVMMWorkerLifecycle(t *testing.T) {
	h := startVMMWorkerHarness(t, vmmBootConfig{MemSize: 1 << 20}, testAssets(t))

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
	workerErr := make(chan error, 1)
	go func() {
		workerErr <- runVMMWorker(ctrlWrk, bridgeWrk, fdWrk, func(vmmBootConfig) (vmmWorkerAssets, error) {
			return testAssets(t), nil
		})
	}()
	nonce := make([]byte, 32)
	if err := workerproto.SendHandshake(ctrlSup, workerproto.RoleVMM, nonce, vmmBootConfig{}); err != nil {
		t.Fatal(err)
	}
	if err := workerproto.WriteNonce(fdSup, nonce); err != nil {
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

// TestVMMWorkerShareOps: hot-add crosses RPC + descriptor transfer into
// the worker's hub, with mirror bookkeeping on the supervisor side.
func TestVMMWorkerShareOps(t *testing.T) {
	h := startVMMWorkerHarness(t, vmmBootConfig{}, testAssets(t))
	serving := workerShareServing{w: h.w}

	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "hello.txt"), []byte("hi"), 0o600); err != nil {
		t.Fatal(err)
	}
	prepared, canon, err := serving.PrepareMapped("docs", root, true, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if canon == "" {
		t.Fatal("no canonical path")
	}
	exp, err := serving.Publish(prepared)
	if err != nil {
		t.Fatal(err)
	}
	if exp.Tag != "docs" || !exp.RO || exp.State() != 0 { // ShareExportActive == 0
		t.Fatalf("mirror export: %+v state %v", exp, exp.State())
	}

	// Replace via swap.
	root2 := t.TempDir()
	prepared2, _, err := serving.PrepareMapped("docs", root2, false, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, exp2, err := serving.Swap(prepared2)
	if err != nil {
		t.Fatal(err)
	}
	if exp2.RO {
		t.Fatal("swap mirror kept RO")
	}

	// Rollback path: prepare + drop (never published).
	prepared3, _, err := serving.PrepareMapped("temp", t.TempDir(), false, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	serving.ClosePrepared(prepared3)

	// Remove.
	gone, err := serving.Remove("docs", true)
	if err != nil {
		t.Fatal(err)
	}
	if gone.State().String() != "gone" {
		t.Fatalf("removed mirror state %v", gone.State())
	}
	// Removing again must fail (the worker hub no longer has it).
	if _, err := serving.Remove("docs", true); err == nil {
		t.Fatal("second remove succeeded")
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
	workerErr := make(chan error, 1)
	go func() {
		workerErr <- runVMMWorker(ctrlWrk, bridgeWrk, fdWrk, func(vmmBootConfig) (vmmWorkerAssets, error) {
			return testAssets(t), nil
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

// TestShareManagerSplitServingLifecycle drives hot-add/remove through a
// REAL ShareManager whose serving backend was detached and replaced by
// the worker RPC (the post-split state): m.hub is nil by design, and
// Add/Remove must flow through the worker's hub regardless.
func TestShareManagerSplitServingLifecycle(t *testing.T) {
	h := startVMMWorkerHarness(t, vmmBootConfig{}, testAssets(t))
	manager, _ := newTestShareManager(t) // zero boot shares, RW

	// Simulate the split: local serving detaches (hub -> nil), the worker
	// RPC backend installs.
	manager.DetachServing()
	if manager.Hub() != nil {
		t.Fatal("hub should be nil after detach")
	}
	manager.SetServing(workerShareServing{w: h.w})

	root := t.TempDir()
	entry, err := manager.Add("docs="+root+",ro", false, false)
	if err != nil {
		t.Fatalf("Add through the worker serving: %v", err)
	}
	if entry.State != "active" || !entry.RO || entry.CtrPath != "/host/docs" {
		t.Fatalf("entry: %+v", entry)
	}
	// The manifest must still advertise the hub transport (the session
	// client mounts /host from it) even though the hub is worker-hosted.
	manifest, err := os.ReadFile(manager.dir + "/shares.json")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(manifest), `"transport"`) {
		t.Fatalf("manifest lost its transport after the split: %s", manifest)
	}
	if _, err := manager.Remove("docs", false, true); err != nil {
		t.Fatalf("Remove through the worker serving: %v", err)
	}
}

func TestVMMKeepFDs(t *testing.T) {
	base := vmmKeepFDs(vmmBootConfig{})
	if base != 8 { // fds 0..7 fixed + kernel at 8
		t.Fatalf("base keepFDs: %d", base)
	}
	full := vmmKeepFDs(vmmBootConfig{HasRoot: true, NDisksRO: 2, NDisks: 1, Shares: []vmmShareMeta{{Tag: "a"}, {Tag: "b"}}, HasKVM: true})
	if full != base+1+2+1+2+1 {
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
// (with a structured error ack) when a core property is not enforced.
func TestVMMWorkerConfinementRequiredRefused(t *testing.T) {
	oldA, oldV := workerconfApplyFn, workerconfVerifyFn
	t.Cleanup(func() { workerconfApplyFn, workerconfVerifyFn = oldA, oldV })
	workerconfApplyFn = func(workerconf.Spec) (*workerconf.Report, error) {
		return &workerconf.Report{Platform: "linux", Applied: true}, nil
	}
	workerconfVerifyFn = func(_ workerconf.Spec, rep *workerconf.Report) {
		rep.Results = []workerconf.PropertyResult{
			{Property: workerconf.PropFSRead, State: workerconf.StateEnforced},
			{Property: workerconf.PropNetDial, State: workerconf.StateUnenforced, Detail: "connection refused"},
			{Property: workerconf.PropExec, State: workerconf.StateEnforced},
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
	workerErr := make(chan error, 1)
	go func() {
		workerErr <- runVMMWorker(ctrlWrk, bridgeWrk, fdWrk, func(vmmBootConfig) (vmmWorkerAssets, error) {
			return testAssets(t), nil
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
	var ack struct {
		OK          bool              `json:"ok"`
		Error       string            `json:"error"`
		Confinement workerconf.Report `json:"confinement"`
	}
	_ = ctrlSup.SetReadDeadline(time.Now().Add(15 * time.Second))
	if err := workerproto.ReadMessage(ctrlSup, &ack); err != nil {
		t.Fatalf("refusal ack: %v", err)
	}
	if ack.OK || !strings.Contains(ack.Error, "required") {
		t.Fatalf("ack: %+v", ack)
	}
	if ack.Confinement.Property(workerconf.PropNetDial).State != workerconf.StateUnenforced {
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
