//go:build linux || darwin

package sandbox

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ejpir/gantry/internal/vmm"
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
		OK    bool   `json:"ok"`
		Error string `json:"error"`
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
		client:  workerproto.NewClient(ctrlSup),
		fdChan:  fdSup,
		bridge:  bridgeSup,
		bridgeE: make(chan error, 1),
		dead:    make(chan struct{}),
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
