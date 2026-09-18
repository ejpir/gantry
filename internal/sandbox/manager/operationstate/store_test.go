package operationstate

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

func TestOperationPhaseTransitions(t *testing.T) {
	for _, terminal := range []Phase{Succeeded, Failed} {
		record := &record{phase: Running}
		if err := record.transition(terminal); err != nil {
			t.Fatalf("running -> %s: %v", terminal, err)
		}
		if record.phase != terminal || record.State != terminal.String() {
			t.Fatalf("transition result phase=%s state=%q", record.phase, record.State)
		}
		if err := record.transition(Failed); err == nil {
			t.Fatalf("terminal phase %s accepted another transition", terminal)
		}
	}
	for _, transition := range []struct{ from, to Phase }{
		{Running, Running},
		{Succeeded, Running},
		{Failed, Succeeded},
	} {
		record := &record{phase: transition.from}
		if err := record.transition(transition.to); err == nil {
			t.Errorf("transition %s -> %s succeeded", transition.from, transition.to)
		}
	}
}

func TestOperationStoreRejectsStaleAndMismatchedUpdates(t *testing.T) {
	store := New(1024, 64, 32)
	started, err := store.Begin("create", "dev", "", "fingerprint")
	if err != nil {
		t.Fatal(err)
	}
	mismatched := started.Owner
	mismatched.generation++
	if err := store.SetProgress(mismatched, "stale"); !errors.Is(err, ErrCompletionRejected) {
		t.Fatalf("mismatched update = %v", err)
	}
	if _, err := store.Finish(started.Owner, nil); err != nil {
		t.Fatal(err)
	}
	if err := store.SetWarnings(started.Owner, []string{"late"}); !errors.Is(err, ErrCompletionRejected) {
		t.Fatalf("late warning update = %v", err)
	}
	if _, err := store.Finish(started.Owner, nil); !errors.Is(err, ErrCompletionRejected) {
		t.Fatalf("duplicate completion = %v", err)
	}
	operation, ok := store.Operation(started.Owner.ID())
	if !ok || operation.State != Succeeded.String() || operation.Progress != "" || len(operation.Warnings) != 0 {
		t.Fatalf("stale update changed operation: %+v", operation)
	}
}

func TestOperationStoreConcurrentCompletionHasOneOwner(t *testing.T) {
	store := New(1024, 64, 32)
	started, err := store.Begin("start", "dev", "", "fingerprint")
	if err != nil {
		t.Fatal(err)
	}
	var succeeded, rejected atomic.Int32
	var callers sync.WaitGroup
	for range 32 {
		callers.Add(1)
		go func() {
			defer callers.Done()
			if _, err := store.Finish(started.Owner, nil); err == nil {
				succeeded.Add(1)
			} else if errors.Is(err, ErrCompletionRejected) {
				rejected.Add(1)
			} else {
				t.Errorf("unexpected completion error: %v", err)
			}
		}()
	}
	callers.Wait()
	if succeeded.Load() != 1 || rejected.Load() != 31 {
		t.Fatalf("completion results: succeeded=%d rejected=%d", succeeded.Load(), rejected.Load())
	}
}

func TestOperationStoreReplayDoesNotGrantCompletionOwnership(t *testing.T) {
	store := New(1024, 64, 32)
	started, err := store.Begin("create", "dev", "key", "fingerprint")
	if err != nil {
		t.Fatal(err)
	}
	replay, err := store.Begin("create", "dev", "key", "fingerprint")
	if err != nil {
		t.Fatal(err)
	}
	if !replay.Replay || replay.Owner.ID() != "" || replay.Phase != Running {
		t.Fatalf("replay unexpectedly owns completion: %+v", replay)
	}
	if _, err := store.Finish(replay.Owner, nil); !errors.Is(err, ErrCompletionRejected) {
		t.Fatalf("replay completion = %v", err)
	}
	if _, err := store.Finish(started.Owner, nil); err != nil {
		t.Fatal(err)
	}
}
