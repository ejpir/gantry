package dashboard

import (
	"testing"

	"github.com/ejpir/gantry/internal/sandbox/dashboardsvc"
)

func TestSandboxTUIRejectsStaleRefreshSnapshot(t *testing.T) {
	model := newSandboxTUIModel(dashboardsvc.NewDashboardService())
	first := model.tuiRefreshState.Current()
	second := model.tuiRefreshState.Restart(false)
	_, _ = model.handleRefresh(tuiRefreshMsg{owner: first, sandboxes: []tuiSandbox{{Name: "stale"}}})
	if len(model.sandboxes) != 0 {
		t.Fatalf("stale snapshot was published: %+v", model.sandboxes)
	}
	_, _ = model.handleRefresh(tuiRefreshMsg{owner: second, sandboxes: []tuiSandbox{{Name: "current"}}})
	if len(model.sandboxes) != 1 || model.sandboxes[0].Name != "current" {
		t.Fatalf("current snapshot was not published: %+v", model.sandboxes)
	}
}
