package dashboard

import "testing"

func TestTUIOperationStateLifecycle(t *testing.T) {
	var state tuiOperationState
	if got := state.phase(); got != tuiOperationIdle {
		t.Fatalf("initial phase = %d, want idle", got)
	}
	if state.begin("", "dev", false) {
		t.Fatal("empty operation was admitted")
	}
	if !state.begin("create", "dev", true) {
		t.Fatal("first operation was refused")
	}
	if got := state.phase(); got != tuiOperationRunning {
		t.Fatalf("phase = %d, want running", got)
	}
	if state.busyAction != "create" || state.busyName != "dev" || state.selectNext != "dev" {
		t.Fatalf("running state = %+v", state)
	}
	if state.begin("stop", "other", false) {
		t.Fatal("second operation was admitted")
	}
	if !state.progress("downloading layer") || state.busyProgress != "downloading layer" {
		t.Fatalf("progress state = %+v", state)
	}
	if state.finish("stop", "dev") {
		t.Fatal("mismatched result finished the operation")
	}
	if !state.finish("create", "dev") {
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
	if state.finish("create", "dev") || state.progress("late") {
		t.Fatal("idle state accepted a terminal event")
	}
}
