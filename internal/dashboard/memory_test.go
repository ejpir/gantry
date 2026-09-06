package dashboard

import (
	"testing"

	"github.com/ejpir/gantry/internal/sandbox/dashboardsvc"
)

func TestMemoryDialogsKeepHostMaximum(t *testing.T) {
	m := newSandboxTUIModel(dashboardsvc.NewDashboardService())
	if m.createMemory.Max != int(m.limits.MaxMemoryMB) || m.editMemory.Max != int(m.limits.MaxMemoryMB) {
		t.Fatal("initial memory sliders do not use the service limit")
	}
	m.limits.MaxMemoryMB = 8192
	m.loading = false
	m.openCreateDialog()
	if m.createMemory.Max != 8192 {
		t.Fatalf("create memory maximum = %d, want 8192", m.createMemory.Max)
	}
	m.sandboxes = []tuiSandbox{{Name: "large", State: tuiRunning, MemMB: 32768, VCPUs: 2}}
	m.cursor = 0
	m.openEditDialog()
	if m.editMemory.Max != 8192 || m.editMemory.Value != 8192 {
		t.Fatalf("oversized existing allocation expanded memory slider: %+v", m.editMemory)
	}
}
