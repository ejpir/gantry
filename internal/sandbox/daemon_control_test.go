package sandbox

import (
	"errors"
	"net"
	"testing"
)

type closeFailureRunner struct {
	done    chan struct{}
	err     error
	calls   int
	onClose func() error
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
