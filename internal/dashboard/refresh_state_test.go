package dashboard

import (
	"testing"

	"github.com/ejpir/gantry/internal/sandbox/dashboardsvc"
)

func TestTUIRefreshStateRejectsStaleCompletion(t *testing.T) {
	state := newTUIRefreshState()
	first := state.current()
	if state.phase() != tuiRefreshRunning {
		t.Fatal("initial refresh is not running")
	}
	if _, ok := state.begin(true); ok {
		t.Fatal("parallel refresh was admitted")
	}
	second := state.restart(false)
	if first == second {
		t.Fatal("replacement refresh reused its owner")
	}
	if state.finish(first) {
		t.Fatal("stale refresh completed its replacement")
	}
	if !state.refreshing || state.refreshVisible {
		t.Fatalf("stale completion changed state: %+v", state)
	}
	if !state.finish(second) || state.phase() != tuiRefreshIdle {
		t.Fatalf("current refresh did not finish: %+v", state)
	}
	if state.finish(second) {
		t.Fatal("duplicate refresh completion was accepted")
	}
}

func TestSandboxTUIRejectsStaleRefreshSnapshot(t *testing.T) {
	model := newSandboxTUIModel(dashboardsvc.NewDashboardService())
	first := model.tuiRefreshState.current()
	second := model.tuiRefreshState.restart(false)
	_, _ = model.handleRefresh(tuiRefreshMsg{owner: first, sandboxes: []tuiSandbox{{Name: "stale"}}})
	if len(model.sandboxes) != 0 {
		t.Fatalf("stale snapshot was published: %+v", model.sandboxes)
	}
	_, _ = model.handleRefresh(tuiRefreshMsg{owner: second, sandboxes: []tuiSandbox{{Name: "current"}}})
	if len(model.sandboxes) != 1 || model.sandboxes[0].Name != "current" {
		t.Fatalf("current snapshot was not published: %+v", model.sandboxes)
	}
}
