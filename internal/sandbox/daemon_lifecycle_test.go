package sandbox

import (
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

var daemonBootPhases = []daemonPhase{
	daemonLoaded,
	daemonHostReady,
	daemonGuestPrepared,
	daemonGuestConnected,
	daemonControlReady,
	daemonReady,
}

func TestDaemonLifecycleHappyPath(t *testing.T) {
	var lifecycle daemonLifecycle
	if got := lifecycle.Phase(); got != daemonNew {
		t.Fatalf("initial phase = %s, want %s", got, daemonNew)
	}
	for _, want := range daemonBootPhases {
		if err := lifecycle.advance(want); err != nil {
			t.Fatalf("advance to %s: %v", want, err)
		}
		if got := lifecycle.Phase(); got != want {
			t.Fatalf("phase = %s, want %s", got, want)
		}
	}
	if !lifecycle.beginStop() {
		t.Fatal("ready lifecycle did not begin stopping")
	}
	if lifecycle.beginStop() {
		t.Fatal("second beginStop reported ownership of shutdown")
	}
	if err := lifecycle.finish(false); err != nil {
		t.Fatal(err)
	}
	if got := lifecycle.Phase(); got != daemonStopped {
		t.Fatalf("terminal phase = %s, want %s", got, daemonStopped)
	}
}

func TestDaemonLifecycleRejectsInvalidTransitions(t *testing.T) {
	var lifecycle daemonLifecycle
	if err := lifecycle.advance(daemonHostReady); err == nil || !strings.Contains(err.Error(), "new -> host-ready") {
		t.Fatalf("skipped transition error = %v", err)
	}
	if got := lifecycle.Phase(); got != daemonNew {
		t.Fatalf("rejected transition changed phase to %s", got)
	}
	if err := lifecycle.advance(daemonLoaded); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.advance(daemonLoaded); err == nil {
		t.Fatal("repeated transition succeeded")
	}
	if err := lifecycle.finish(false); err == nil {
		t.Fatal("finish before stopping succeeded")
	}
	if !lifecycle.beginStop() {
		t.Fatal("beginStop failed")
	}
	if err := lifecycle.advance(daemonHostReady); err == nil {
		t.Fatal("boot transition while stopping succeeded")
	}
	if err := lifecycle.finish(true); err != nil {
		t.Fatal(err)
	}
	if got := lifecycle.Phase(); got != daemonFailed {
		t.Fatalf("terminal phase = %s, want %s", got, daemonFailed)
	}
	if lifecycle.beginStop() {
		t.Fatal("terminal lifecycle restarted shutdown")
	}
	if err := lifecycle.finish(false); err == nil {
		t.Fatal("terminal outcome was replaced")
	}
}

func TestDaemonLifecycleCanStopFromEveryLivePhase(t *testing.T) {
	live := append([]daemonPhase{daemonNew}, daemonBootPhases...)
	for index, phase := range live {
		t.Run(phase.String(), func(t *testing.T) {
			var lifecycle daemonLifecycle
			for _, next := range daemonBootPhases[:index] {
				if err := lifecycle.advance(next); err != nil {
					t.Fatal(err)
				}
			}
			if got := lifecycle.Phase(); got != phase {
				t.Fatalf("setup phase = %s, want %s", got, phase)
			}
			if !lifecycle.beginStop() {
				t.Fatal("beginStop returned false")
			}
			if err := lifecycle.finish(true); err != nil {
				t.Fatal(err)
			}
			if got := lifecycle.Phase(); got != daemonFailed {
				t.Fatalf("terminal phase = %s, want %s", got, daemonFailed)
			}
		})
	}
}

func TestDaemonLifecycleHasOneShutdownOwner(t *testing.T) {
	var lifecycle daemonLifecycle
	var owners atomic.Int32
	var group sync.WaitGroup
	for range 32 {
		group.Add(1)
		go func() {
			defer group.Done()
			if lifecycle.beginStop() {
				owners.Add(1)
			}
		}()
	}
	group.Wait()
	if got := owners.Load(); got != 1 {
		t.Fatalf("shutdown owners = %d, want 1", got)
	}
	if got := lifecycle.Phase(); got != daemonStopping {
		t.Fatalf("phase = %s, want %s", got, daemonStopping)
	}
}
