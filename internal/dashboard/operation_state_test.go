package dashboard

import "testing"

func TestTUIOperationStateLifecycle(t *testing.T) {
	var state tuiOperationState
	if got := state.phase(); got != tuiOperationIdle {
		t.Fatalf("initial phase = %d, want idle", got)
	}
	if _, ok := state.begin("", "dev", false); ok {
		t.Fatal("empty operation was admitted")
	}
	owner, ok := state.begin("create", "dev", true)
	if !ok {
		t.Fatal("first operation was refused")
	}
	if got := state.phase(); got != tuiOperationRunning {
		t.Fatalf("phase = %d, want running", got)
	}
	if state.busyAction != "create" || state.busyName != "dev" || state.selectNext != "dev" {
		t.Fatalf("running state = %+v", state)
	}
	if _, ok := state.begin("stop", "other", false); ok {
		t.Fatal("second operation was admitted")
	}
	if !state.progress(owner, "downloading layer") || state.busyProgress != "downloading layer" {
		t.Fatalf("progress state = %+v", state)
	}
	mismatched := owner
	mismatched.generation++
	if state.finish(mismatched) {
		t.Fatal("mismatched result finished the operation")
	}
	if !state.finish(owner) {
		t.Fatal("running operation did not finish")
	}
	if got := state.phase(); got != tuiOperationIdle {
		t.Fatalf("terminal phase = %d, want idle", got)
	}
	if state.busyAction != "" || state.busyName != "" || state.busyProgress != "" {
		t.Fatalf("finished operation retained live fields: %+v", state)
	}
	if state.selectNext != "dev" {
		t.Fatalf("finish discarded selection handoff %q", state.selectNext)
	}
	state.clearSelection()
	if state.selectNext != "" {
		t.Fatalf("selection handoff was not cleared: %q", state.selectNext)
	}
	if state.finish(owner) || state.progress(owner, "late") {
		t.Fatal("idle state accepted a terminal event")
	}
}

func TestTUIOperationStateRejectsReplayedOwnerForSameAction(t *testing.T) {
	var state tuiOperationState
	first, ok := state.begin("start", "dev", false)
	if !ok || !state.finish(first) {
		t.Fatal("first operation did not complete")
	}
	second, ok := state.begin("start", "dev", false)
	if !ok {
		t.Fatal("replacement operation was not admitted")
	}
	if first == second {
		t.Fatal("replacement reused its completion capability")
	}
	if state.progress(first, "stale") || state.finish(first) {
		t.Fatal("replayed owner updated the replacement operation")
	}
	if !state.finish(second) {
		t.Fatal("replacement owner could not complete")
	}
}
