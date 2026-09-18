package manager

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

func TestOperationPhaseTransitions(t *testing.T) {
	for _, terminal := range []operationPhase{operationSucceeded, operationFailed} {
		record := &operationRecord{phase: operationRunning}
		if err := record.transition(terminal); err != nil {
			t.Fatalf("running -> %s: %v", terminal, err)
		}
		if record.phase != terminal || record.State != terminal.String() {
			t.Fatalf("transition result phase=%s state=%q", record.phase, record.State)
		}
		if err := record.transition(operationFailed); err == nil {
			t.Fatalf("terminal phase %s accepted another transition", terminal)
		}
	}
	for _, transition := range []struct{ from, to operationPhase }{
		{operationRunning, operationRunning},
		{operationSucceeded, operationRunning},
		{operationFailed, operationSucceeded},
	} {
		record := &operationRecord{phase: transition.from}
		if err := record.transition(transition.to); err == nil {
			t.Errorf("transition %s -> %s succeeded", transition.from, transition.to)
		}
	}
}

func TestOperationStoreRejectsStaleAndMismatchedUpdates(t *testing.T) {
	store := newOperationStore()
	started, err := store.begin("create", "dev", "", "fingerprint")
	if err != nil {
		t.Fatal(err)
	}
	mismatched := started.Owner
	mismatched.generation++
	if err := store.setProgress(mismatched, "stale"); !errors.Is(err, errOperationCompletionRejected) {
		t.Fatalf("mismatched update = %v", err)
	}
	if _, err := store.finish(started.Owner, nil); err != nil {
		t.Fatal(err)
	}
	if err := store.setWarnings(started.Owner, []string{"late"}); !errors.Is(err, errOperationCompletionRejected) {
		t.Fatalf("late warning update = %v", err)
	}
	if _, err := store.finish(started.Owner, nil); !errors.Is(err, errOperationCompletionRejected) {
		t.Fatalf("duplicate completion = %v", err)
	}
	operation, ok := store.operation(started.Owner.ID())
	if !ok || operation.State != operationSucceeded.String() || operation.Progress != "" || len(operation.Warnings) != 0 {
		t.Fatalf("stale update changed operation: %+v", operation)
	}
}

func TestOperationStoreConcurrentCompletionHasOneOwner(t *testing.T) {
	store := newOperationStore()
	started, err := store.begin("start", "dev", "", "fingerprint")
	if err != nil {
		t.Fatal(err)
	}
	var succeeded, rejected atomic.Int32
	var callers sync.WaitGroup
	for range 32 {
		callers.Add(1)
		go func() {
			defer callers.Done()
			if _, err := store.finish(started.Owner, nil); err == nil {
				succeeded.Add(1)
			} else if errors.Is(err, errOperationCompletionRejected) {
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
	store := newOperationStore()
	started, err := store.begin("create", "dev", "key", "fingerprint")
	if err != nil {
		t.Fatal(err)
	}
	replay, err := store.begin("create", "dev", "key", "fingerprint")
	if err != nil {
		t.Fatal(err)
	}
	if !replay.Replay || replay.Owner.ID() != "" || replay.Phase != operationRunning {
		t.Fatalf("replay unexpectedly owns completion: %+v", replay)
	}
	if _, err := store.finish(replay.Owner, nil); !errors.Is(err, errOperationCompletionRejected) {
		t.Fatalf("replay completion = %v", err)
	}
	if _, err := store.finish(started.Owner, nil); err != nil {
		t.Fatal(err)
	}
}
