package operationstate

import "testing"

func TestStateLifecycle(t *testing.T) {
	var state State
	if got := state.Phase(); got != Idle {
		t.Fatalf("initial phase = %d, want idle", got)
	}
	if _, ok := state.Begin("", "dev", false); ok {
		t.Fatal("empty operation was admitted")
	}
	owner, ok := state.Begin("create", "dev", true)
	if !ok {
		t.Fatal("first operation was refused")
	}
	if got := state.Phase(); got != Running {
		t.Fatalf("phase = %d, want running", got)
	}
	if state.Action() != "create" || state.Name() != "dev" || state.Selection() != "dev" {
		t.Fatalf("running state = %+v", state)
	}
	if _, ok := state.Begin("stop", "other", false); ok {
		t.Fatal("second operation was admitted")
	}
	if !state.SetProgress(owner, "downloading layer") || state.Progress() != "downloading layer" {
		t.Fatalf("progress state = %+v", state)
	}
	mismatched := owner
	mismatched.generation++
	if state.Finish(mismatched) {
		t.Fatal("mismatched result finished the operation")
	}
	if !state.Finish(owner) {
		t.Fatal("running operation did not finish")
	}
	if got := state.Phase(); got != Idle {
		t.Fatalf("terminal phase = %d, want idle", got)
	}
	if state.Action() != "" || state.Name() != "" || state.Progress() != "" {
		t.Fatalf("finished operation retained live fields: %+v", state)
	}
	if state.Selection() != "dev" {
		t.Fatalf("finish discarded selection handoff %q", state.Selection())
	}
	state.ClearSelection()
	if state.Selection() != "" {
		t.Fatalf("selection handoff was not cleared: %q", state.Selection())
	}
	if state.Finish(owner) || state.SetProgress(owner, "late") {
		t.Fatal("idle state accepted a terminal event")
	}
}

func TestStateRejectsReplayedOwnerForSameAction(t *testing.T) {
	var state State
	first, ok := state.Begin("start", "dev", false)
	if !ok || !state.Finish(first) {
		t.Fatal("first operation did not complete")
	}
	second, ok := state.Begin("start", "dev", false)
	if !ok {
		t.Fatal("replacement operation was not admitted")
	}
	if first == second {
		t.Fatal("replacement reused its completion capability")
	}
	if state.SetProgress(first, "stale") || state.Finish(first) {
		t.Fatal("replayed owner updated the replacement operation")
	}
	if !state.Finish(second) {
		t.Fatal("replacement owner could not complete")
	}
}
