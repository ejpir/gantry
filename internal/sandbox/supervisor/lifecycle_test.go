package supervisor

import (
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

var bootPhases = []Phase{Loaded, HostReady, GuestPrepared, GuestConnected, ControlReady, Ready}

func TestLifecycleHappyPath(t *testing.T) {
	var lifecycle Lifecycle
	if got := lifecycle.Phase(); got != New {
		t.Fatalf("initial phase = %s, want %s", got, New)
	}
	for _, want := range bootPhases {
		if err := lifecycle.Advance(want); err != nil {
			t.Fatalf("advance to %s: %v", want, err)
		}
		if got := lifecycle.Phase(); got != want {
			t.Fatalf("phase = %s, want %s", got, want)
		}
	}
	if !lifecycle.BeginStop() {
		t.Fatal("ready lifecycle did not begin stopping")
	}
	if lifecycle.BeginStop() {
		t.Fatal("second BeginStop reported ownership of shutdown")
	}
	if err := lifecycle.Finish(false); err != nil {
		t.Fatal(err)
	}
	if got := lifecycle.Phase(); got != Stopped {
		t.Fatalf("terminal phase = %s, want %s", got, Stopped)
	}
}

func TestLifecycleRejectsInvalidTransitions(t *testing.T) {
	var lifecycle Lifecycle
	if err := lifecycle.Advance(HostReady); err == nil || !strings.Contains(err.Error(), "new -> host-ready") {
		t.Fatalf("skipped transition error = %v", err)
	}
	if got := lifecycle.Phase(); got != New {
		t.Fatalf("rejected transition changed phase to %s", got)
	}
	if err := lifecycle.Advance(Loaded); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Advance(Loaded); err == nil {
		t.Fatal("repeated transition succeeded")
	}
	if err := lifecycle.Finish(false); err == nil {
		t.Fatal("finish before stopping succeeded")
	}
	if !lifecycle.BeginStop() {
		t.Fatal("BeginStop failed")
	}
	if err := lifecycle.Advance(HostReady); err == nil {
		t.Fatal("boot transition while stopping succeeded")
	}
	if err := lifecycle.Finish(true); err != nil {
		t.Fatal(err)
	}
	if got := lifecycle.Phase(); got != Failed {
		t.Fatalf("terminal phase = %s, want %s", got, Failed)
	}
	if lifecycle.BeginStop() {
		t.Fatal("terminal lifecycle restarted shutdown")
	}
	if err := lifecycle.Finish(false); err == nil {
		t.Fatal("terminal outcome was replaced")
	}
}

func TestLifecycleCanStopFromEveryLivePhase(t *testing.T) {
	live := append([]Phase{New}, bootPhases...)
	for index, phase := range live {
		t.Run(phase.String(), func(t *testing.T) {
			var lifecycle Lifecycle
			for _, next := range bootPhases[:index] {
				if err := lifecycle.Advance(next); err != nil {
					t.Fatal(err)
				}
			}
			if got := lifecycle.Phase(); got != phase {
				t.Fatalf("setup phase = %s, want %s", got, phase)
			}
			if !lifecycle.BeginStop() {
				t.Fatal("BeginStop returned false")
			}
			if err := lifecycle.Finish(true); err != nil {
				t.Fatal(err)
			}
			if got := lifecycle.Phase(); got != Failed {
				t.Fatalf("terminal phase = %s, want %s", got, Failed)
			}
		})
	}
}

func TestLifecycleHasOneShutdownOwner(t *testing.T) {
	var lifecycle Lifecycle
	var owners atomic.Int32
	var group sync.WaitGroup
	for range 32 {
		group.Add(1)
		go func() {
			defer group.Done()
			if lifecycle.BeginStop() {
				owners.Add(1)
			}
		}()
	}
	group.Wait()
	if got := owners.Load(); got != 1 {
		t.Fatalf("shutdown owners = %d, want 1", got)
	}
	if got := lifecycle.Phase(); got != Stopping {
		t.Fatalf("phase = %s, want %s", got, Stopping)
	}
}
