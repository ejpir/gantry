package guestplane

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/ejpir/gantry/internal/netpol"
	"github.com/ejpir/gantry/internal/packetcapture"
)

type fakeRunner struct {
	done      chan struct{}
	closeOnce sync.Once
	closes    atomic.Int32
}

func (r *fakeRunner) Wait() error { <-r.done; return nil }
func (r *fakeRunner) Close() error {
	r.closes.Add(1)
	r.closeOnce.Do(func() { close(r.done) })
	return nil
}
func (*fakeRunner) RequestHotMemory() error { return nil }
func (r *fakeRunner) Done() <-chan struct{} { return r.done }
func (*fakeRunner) Err() error              { return nil }
func (*fakeRunner) DialStream(uint32) (net.Conn, error) {
	return nil, errors.New("unused")
}
func (*fakeRunner) SetPolicy(*netpol.Policy) error { return nil }
func (*fakeRunner) Capture(packetcapture.Request) (packetcapture.Snapshot, error) {
	return packetcapture.Snapshot{}, nil
}

func TestPlaneOwnsRunnerAndHidesCloseFromBorrowers(t *testing.T) {
	runner := &fakeRunner{done: make(chan struct{})}
	var plane Plane
	plane.SetRunner(runner)
	plane.Start()

	borrowed := []any{plane.Runner(), plane.PolicyPusher(), plane.PacketCapture()}
	for _, capability := range borrowed {
		if capability == nil {
			t.Fatalf("missing borrowed capability")
		}
		if _, ok := capability.(interface{ Close() error }); ok {
			t.Fatalf("borrowed capability %T exposes Close", capability)
		}
	}

	if err := plane.Close(); err != nil {
		t.Fatal(err)
	}
	if err := plane.Close(); err != nil {
		t.Fatal(err)
	}
	if got := runner.closes.Load(); got != 1 {
		t.Fatalf("runner Close calls = %d, want 1", got)
	}
}
