//go:build linux || darwin || windows

package sharefs

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestDeferredFinalizersStopAdmissionAndJoinWorkers(t *testing.T) {
	var owner deferredFinalizers
	started := make(chan struct{})
	release := make(chan struct{})
	if !owner.schedule(func() {
		close(started)
		<-release
	}) {
		t.Fatal("active owner rejected a finalizer")
	}
	<-started
	owner.stopAdmission()
	var late atomic.Bool
	if owner.schedule(func() { late.Store(true) }) {
		t.Fatal("stopping owner admitted a finalizer")
	}
	joined := make(chan struct{})
	go func() {
		owner.wait()
		close(joined)
	}()
	select {
	case <-joined:
		t.Fatal("wait returned before the worker exited")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	select {
	case <-joined:
	case <-time.After(time.Second):
		t.Fatal("wait did not join the released worker")
	}
	if late.Load() {
		t.Fatal("rejected finalizer ran")
	}
}
