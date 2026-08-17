package sandbox

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

type closeFailureRunner struct {
	done     chan struct{}
	err      error
	calls    int
	hotCalls atomic.Int32
	onClose  func() error
}

func (*closeFailureRunner) Wait() error { return nil }
func (r *closeFailureRunner) Close() error {
	r.calls++
	if r.onClose != nil {
		return errors.Join(r.err, r.onClose())
	}
	return r.err
}
func (r *closeFailureRunner) Done() <-chan struct{}             { return r.done }
func (r *closeFailureRunner) Err() error                        { return nil }
func (r *closeFailureRunner) RequestHotMemory() error           { r.hotCalls.Add(1); return nil }
func (*closeFailureRunner) DialStream(uint32) (net.Conn, error) { return nil, errors.New("unused") }

func TestCloseVMDevicesPreservesSplitWorkerFailure(t *testing.T) {
	want := errors.New("disk flush failed")
	runner := &closeFailureRunner{done: make(chan struct{}), err: want}
	runtime := &daemonRuntime{runner: runner}

	if err := runtime.closeVMDevices(); !errors.Is(err, want) {
		t.Fatalf("closeVMDevices() = %v, want %v", err, want)
	}
	if runner.calls != 1 {
		t.Fatalf("runner Close called %d times", runner.calls)
	}
	if runtime.runner != nil {
		t.Fatal("closed runner retained for deferred teardown")
	}
}

func TestPublishReadyRequiresListeningControlBroker(t *testing.T) {
	dir := t.TempDir()
	runtime := &daemonRuntime{dir: dir}
	if err := runtime.publishReady(); err == nil {
		t.Fatal("publishReady succeeded without a control listener")
	}
	if _, err := os.Stat(filepath.Join(dir, "ready")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ready marker before control startup: %v", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	runtime.control = listener
	runtime.broker = &broker{}
	runner := &closeFailureRunner{done: make(chan struct{})}
	runtime.runner = runner
	if err := runtime.publishReady(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for runner.hotCalls.Load() != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if calls := runner.hotCalls.Load(); calls != 1 {
		t.Fatalf("post-readiness hot-memory requests = %d, want 1", calls)
	}
	if _, err := os.Stat(filepath.Join(dir, "ready")); err != nil {
		t.Fatalf("ready marker after control startup: %v", err)
	}
}
