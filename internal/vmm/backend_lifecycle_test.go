package vmm

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestNativeBackendCloseJoinsWorkersBeforeRelease(t *testing.T) {
	lifecycle := newNativeBackendLifecycle(3)
	if !lifecycle.claimWorker() {
		t.Fatal("main worker reservation unavailable")
	}

	workerStarted := make(chan struct{})
	workerDone := make(chan struct{})
	go func() {
		lifecycle.runWorker(func(stop <-chan struct{}) {
			close(workerStarted)
			<-stop
			close(workerDone)
		})
	}()
	<-workerStarted

	var released atomic.Bool
	closed := make(chan error, 1)
	go func() {
		closed <- lifecycle.close(func() error { return nil }, func() error {
			released.Store(true)
			return nil
		})
	}()

	select {
	case <-workerDone:
	case <-time.After(time.Second):
		t.Fatal("stop did not wake the worker")
	}
	if released.Load() {
		t.Fatal("native resources released while main worker was active")
	}

	lifecycle.workerDone()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not abandon the unstarted reservation")
	}
	if !released.Load() {
		t.Fatal("native resources were not released")
	}
	called := false
	lifecycle.runWorker(func(<-chan struct{}) {
		called = true
	})
	if called {
		t.Fatal("worker started after Close abandoned its reservation")
	}
}

func TestNativeBackendCloseIsConcurrentAndIdempotent(t *testing.T) {
	lifecycle := newNativeBackendLifecycle(0)
	var kicks, releases atomic.Int32
	closeBackend := func() error {
		return lifecycle.close(func() error {
			kicks.Add(1)
			return nil
		}, func() error {
			releases.Add(1)
			return nil
		})
	}

	var callers sync.WaitGroup
	for range 8 {
		callers.Add(1)
		go func() {
			defer callers.Done()
			if err := closeBackend(); err != nil {
				t.Errorf("Close: %v", err)
			}
		}()
	}
	callers.Wait()
	if got := kicks.Load(); got != 1 {
		t.Fatalf("kick calls = %d, want 1", got)
	}
	if got := releases.Load(); got != 1 {
		t.Fatalf("release calls = %d, want 1", got)
	}
}

func TestNativeBackendCloseJoinsCallbackErrors(t *testing.T) {
	lifecycle := newNativeBackendLifecycle(1)
	kickErr := errors.New("kick")
	workerErr := errors.New("worker")
	releaseErr := errors.New("release")
	workerStarted := make(chan struct{})
	go lifecycle.runWorker(func(stop <-chan struct{}) {
		close(workerStarted)
		<-stop
		lifecycle.recordError(workerErr)
	})
	<-workerStarted
	err := lifecycle.close(func() error { return kickErr }, func() error { return releaseErr })
	if !errors.Is(err, kickErr) || !errors.Is(err, workerErr) || !errors.Is(err, releaseErr) {
		t.Fatalf("Close error = %v, want kick, worker, and release failures", err)
	}
	if again := lifecycle.close(nil, nil); !errors.Is(again, kickErr) ||
		!errors.Is(again, workerErr) || !errors.Is(again, releaseErr) {
		t.Fatalf("second Close error = %v, want stable first result", again)
	}
}

func TestNativeThreadTeardownReleasesOwnersTogether(t *testing.T) {
	teardown := newNativeThreadTeardown(2)
	arrived := make(chan struct{}, 2)
	released := make(chan int, 2)
	for id := range 2 {
		go func() {
			arrived <- struct{}{}
			teardown.finishOwner(func() { released <- id })
		}()
	}
	<-arrived
	<-arrived
	select {
	case id := <-released:
		t.Fatalf("owner %d released before the teardown barrier", id)
	default:
	}

	teardown.releaseOwners()
	for range 2 {
		select {
		case <-released:
		case <-time.After(time.Second):
			t.Fatal("owner did not finish thread-affine teardown")
		}
	}
	// Concurrent Close callers may all reach the same barrier.
	teardown.releaseOwners()
}

func TestNativeBackendCloseCoordinatesThreadAffineTeardown(t *testing.T) {
	lifecycle := newNativeBackendLifecycle(2)
	teardown := newNativeThreadTeardown(2)
	if !lifecycle.claimWorker() {
		t.Fatal("main worker reservation unavailable")
	}

	secondaryStarted := make(chan struct{})
	secondaryReleased := make(chan struct{})
	go lifecycle.runWorker(func(stop <-chan struct{}) {
		close(secondaryStarted)
		<-stop
		teardown.finishOwner(func() { close(secondaryReleased) })
	})
	<-secondaryStarted

	resourcesReleased := make(chan struct{})
	closed := make(chan error, 1)
	go func() {
		closed <- lifecycle.close(func() error {
			teardown.releaseOwners()
			return nil
		}, func() error {
			select {
			case <-secondaryReleased:
			default:
				t.Error("native resource release preceded vCPU destruction")
			}
			close(resourcesReleased)
			return nil
		})
	}()

	mainReleased := make(chan struct{})
	teardown.finishOwner(func() { close(mainReleased) })
	select {
	case <-mainReleased:
	case <-time.After(time.Second):
		t.Fatal("main owner did not complete thread-affine teardown")
	}
	lifecycle.workerDone()

	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not finish after all vCPUs were destroyed")
	}
	select {
	case <-resourcesReleased:
	default:
		t.Fatal("native resources were not released")
	}
}
