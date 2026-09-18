package refreshstate

import "testing"

func TestStateRejectsStaleCompletion(t *testing.T) {
	state := New()
	first := state.Current()
	if state.Phase() != Running {
		t.Fatal("initial refresh is not running")
	}
	if _, ok := state.Begin(true); ok {
		t.Fatal("parallel refresh was admitted")
	}
	second := state.Restart(false)
	if first == second {
		t.Fatal("replacement refresh reused its owner")
	}
	if state.Finish(first) {
		t.Fatal("stale refresh completed its replacement")
	}
	if !state.Refreshing() || state.Visible() {
		t.Fatalf("stale completion changed state: %+v", state)
	}
	if !state.Finish(second) || state.Phase() != Idle {
		t.Fatalf("current refresh did not finish: %+v", state)
	}
	if state.Finish(second) {
		t.Fatal("duplicate refresh completion was accepted")
	}
}
