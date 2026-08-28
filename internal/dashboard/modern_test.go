package dashboard

import (
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/ejpir/gantry/internal/sandbox/dashboardsvc"
)

func modernDashboardTestModel() sandboxTUIModel {
	m := newSandboxTUIModel(dashboardsvc.NewDashboardService())
	m.loading = false
	m.refreshing = false
	m.width, m.height = 170, 40
	m.lastUpdate = time.Now().Add(-5 * time.Second)
	m.sandboxes = []tuiSandbox{
		{
			Name: "codex-dev", State: tuiRunning, Image: "docker.io/library/codex-dev-pre-host-relays:v1", Runtime: "crun",
			MemMB: 23905, VCPUs: 12, RW: true, RWLayer: "/layers/codex-dev.ext4", DiskSizeMiB: 60 << 10,
			Net: true, TXBytes: 25 << 30, RXBytes: 22 << 30, Shares: 4, Ports: 1, SecretCount: 2,
			SSH: true, DevContainers: true, DevContainersImage: "gantry-ide:latest",
			DevContainersRWLayer: "/layers/codex-dev@devcontainers.ext4", DevContainersDiskMiB: 32 << 10,
			Updated: time.Now().Add(-time.Hour),
		},
		{Name: "testnick", State: tuiRunning, Image: "docker.io/library/ubuntu:latest", Runtime: "crun", MemMB: 4096, VCPUs: 4, RW: true, DiskSizeMiB: 32 << 10},
	}
	m.rules = make([]tuiRuleRow, 36)
	m.mounts = make([]tuiMountRow, 4)
	m.ports = make([]tuiPortRow, 1)
	m.images = make([]tuiImageRow, 5)
	return m
}

func TestOperationalDashboardUsesWideSidebarAndHealthCards(t *testing.T) {
	m := modernDashboardTestModel()
	m.page = tuiOverviewPage
	view := m.View().Content
	plain := ansi.Strip(view)
	for _, want := range []string{
		"Workspace", "[0] Overview", "[1] Sandboxes", "Network rules", "Overview",
		"Sandboxes", "2 running", "Network", "Storage", "Security", "SANDBOX HEALTH",
		"codex-dev", "23.3 GiB RAM", "60 GiB disk", "SSH · Dev Containers", "New sandbox",
	} {
		if !strings.Contains(plain, want) {
			t.Fatalf("operational dashboard missing %q:\n%s", want, plain)
		}
	}
	if got := lipgloss.Width(view); got != m.width {
		t.Fatalf("overview width = %d, want %d", got, m.width)
	}
	if got := lipgloss.Height(view); got != m.height {
		t.Fatalf("overview height = %d, want %d", got, m.height)
	}
}

func TestSandboxMasterDetailRendersWorkloadAndDevelopmentTopology(t *testing.T) {
	m := modernDashboardTestModel()
	m.page = tuiSandboxesPage
	plain := ansi.Strip(m.View().Content)
	for _, want := range []string{
		"codex-dev", "microVM", "12 vCPU", "23.3 GiB RAM", "Workload", "Development",
		"codex-dev-pre-host-relays:v1", "gantry-ide:latest", "32 GiB IDE disk",
		"Podman Dev Containers", "22.0 GiB", "25.0 GiB", "4 mounts · 1 port · 2 secrets",
	} {
		if !strings.Contains(plain, want) {
			t.Fatalf("master-detail topology missing %q:\n%s", want, plain)
		}
	}
}

func TestOverviewEnterOpensSelectedSandboxTopology(t *testing.T) {
	m := modernDashboardTestModel()
	m.page = tuiOverviewPage
	m.cursor = 0
	model, cmd := m.updateKey(tea.KeyPressMsg{Code: tea.KeyEnter})
	m = *model.(*sandboxTUIModel)
	if cmd != nil || m.page != tuiSandboxesPage || m.cursor != 0 {
		t.Fatalf("overview enter = page %d cursor %d cmd=%v", m.page, m.cursor, cmd)
	}
}

func TestWideSidebarNavigationAndGlobalNewAction(t *testing.T) {
	m := modernDashboardTestModel()
	_ = m.View()
	imagesTarget := tuiHitTarget{}
	for _, target := range m.dashboardHits {
		if target.kind == "page" && target.page == tuiImagesPage {
			imagesTarget = target
			break
		}
	}
	if imagesTarget.rect.w == 0 {
		t.Fatal("Images sidebar row has no render-produced target")
	}
	model, cmd := m.updateMouseClick(tea.Mouse{X: imagesTarget.rect.x + imagesTarget.rect.w/2, Y: imagesTarget.rect.y, Button: tea.MouseLeft})
	m = *model.(*sandboxTUIModel)
	if cmd != nil || m.page != tuiImagesPage {
		t.Fatalf("sidebar image click = page %d cmd=%v", m.page, cmd)
	}
	model, cmd = m.updateKey(tea.KeyPressMsg{Code: 'n'})
	m = *model.(*sandboxTUIModel)
	if cmd == nil || m.dialog != tuiCreateDialog {
		t.Fatalf("global new = dialog %d cmd=%v", m.dialog, cmd)
	}
}

func TestBusyDashboardIgnoresMouseCreationActions(t *testing.T) {
	m := modernDashboardTestModel()
	m.busyAction = "start"
	m.busyName = "codex-dev"
	_ = m.View()
	for _, target := range m.dashboardHits {
		if target.kind != "menu" || target.action != "new" {
			continue
		}
		model, cmd := m.dispatchDashboardHit(target)
		m = *model.(*sandboxTUIModel)
		if cmd != nil || m.dialog != tuiNoDialog {
			t.Fatalf("busy New click = dialog %d cmd=%v", m.dialog, cmd)
		}
	}
}

func TestCreateSandboxModalUsesSectionsAndDependencyCopy(t *testing.T) {
	m := modernDashboardTestModel()
	m.openCreateDialog()
	plain := ansi.Strip(m.renderCreateDialog(tuiThemeFor(m.dark), 66))
	for _, want := range []string{"Create sandbox", "IDENTITY", "RUNTIME", "DEVELOPMENT", "RESOURCES", "SECURITY", "[ ] Disabled", "Cancel"} {
		if !strings.Contains(plain, want) {
			t.Fatalf("create modal missing %q:\n%s", want, plain)
		}
	}
	m.createFocus = 5
	m.adjustCreateChoice(1)
	plain = ansi.Strip(m.renderCreateDialog(tuiThemeFor(m.dark), 66))
	for _, want := range []string{"[✓] Enabled", "SSH and crun enabled automatically", "IDE disk follows Persistent disk"} {
		if !strings.Contains(plain, want) {
			t.Fatalf("Dev Containers modal missing %q:\n%s", want, plain)
		}
	}
}

func TestDashboardHitMapUsesRenderedGeometry(t *testing.T) {
	for _, size := range [][2]int{{40, 16}, {70, 22}, {100, 30}, {119, 34}, {120, 20}, {120, 34}, {170, 40}} {
		m := modernDashboardTestModel()
		m.width, m.height = size[0], size[1]
		for page := tuiSandboxesPage; page < tuiPageCount; page++ {
			m.page = page
			layout := m.dashboardLayout()
			_ = m.View() // View publishes the exact hit map emitted by this frame.
			targets := append([]tuiHitTarget(nil), m.dashboardHits...)
			if len(targets) == 0 {
				t.Fatalf("%dx%d page %d has no hit targets", m.width, m.height, page)
			}
			for _, want := range targets {
				if want.rect.w <= 0 || want.rect.h <= 0 || want.rect.x < 0 || want.rect.y < 0 || want.rect.x+want.rect.w > m.width || want.rect.y+want.rect.h > m.height {
					t.Fatalf("%dx%d page %d target %s has invalid rect %+v", m.width, m.height, page, want.String(), want.rect)
				}
				x, y := want.rect.x+want.rect.w/2, want.rect.y+want.rect.h/2
				got, ok := m.dashboardHitAt(layout, x, y)
				if !ok {
					t.Fatalf("%dx%d page %d target %s center (%d,%d) is not clickable", m.width, m.height, page, want.String(), x, y)
				}
				if got.kind != want.kind || got.action != want.action || got.page != want.page || got.index != want.index {
					t.Fatalf("%dx%d page %d target %s center resolved to %s (want page=%d index=%d, got page=%d index=%d)", m.width, m.height, page, want.String(), got.String(), want.page, want.index, got.page, got.index)
				}
			}
		}
	}
}

func TestWideLayoutSeparatesHeaderAndAlignsWorkspaceSection(t *testing.T) {
	m := modernDashboardTestModel()
	m.page = tuiTrafficPage
	m.traffic = []tuiTrafficRow{{Sandbox: "codex-dev", Host: "example.com", Protocol: "tcp", Allowed: true}}
	lines := strings.Split(ansi.Strip(m.View().Content), "\n")
	layout := m.dashboardLayout()
	if got := layout.contentY - tuiMenuHeight; got != tuiWideContentGap {
		t.Fatalf("wide header gap = %d, want %d", got, tuiWideContentGap)
	}
	rowOf := func(needle string) int {
		t.Helper()
		for row, line := range lines {
			if strings.Contains(line, needle) {
				return row
			}
		}
		t.Fatalf("rendered screen missing %q", needle)
		return -1
	}
	if got := rowOf("Workspace"); got != layout.contentY+1 {
		t.Fatalf("Workspace row = %d, want panel title row %d", got, layout.contentY+1)
	}
	if got := rowOf("STATUS"); got != layout.contentY {
		t.Fatalf("table header row = %d, want content row %d", got, layout.contentY)
	}
	topBorder := lines[layout.contentY]
	if !strings.Contains(topBorder, "╭") || !strings.Contains(topBorder, "╮") {
		t.Fatalf("Workspace panel has no top border: %q", topBorder)
	}
}

func TestRenderedRowsAndHitMapShareTerminalCoordinates(t *testing.T) {
	m := modernDashboardTestModel()
	m.page = tuiOverviewPage
	plain := strings.Split(ansi.Strip(m.View().Content), "\n")
	find := func(needle string) (int, int) {
		t.Helper()
		for y, line := range plain {
			if x := strings.Index(line, needle); x >= 0 {
				return x, y
			}
		}
		t.Fatalf("rendered screen does not contain %q", needle)
		return 0, 0
	}
	assertTarget := func(needle, kind, action string, page tuiPage) {
		t.Helper()
		x, y := find(needle)
		hit, ok := m.dashboardHitAt(m.dashboardLayout(), x+len(needle)/2, y)
		if !ok || hit.kind != kind || hit.action != action || (kind == "page" && hit.page != page) {
			t.Fatalf("rendered %q at (%d,%d) resolved to %#v, %t", needle, x, y, hit, ok)
		}
	}
	assertTarget("[0] Overview", "page", "", tuiOverviewPage)
	assertTarget("[1] Sandboxes", "page", "", tuiSandboxesPage)
	assertTarget("enter inspect", "shortcut", "enter", 0)
	assertTarget("n  New sandbox", "menu", "new", 0)
}

func TestStatusBarActionsAreClickableAtTheirRenderedText(t *testing.T) {
	m := modernDashboardTestModel()
	m.page = tuiSandboxesPage
	_ = m.View()
	found := map[string]bool{}
	layout := m.dashboardLayout()
	for _, target := range m.dashboardHits {
		if target.kind != "shortcut" {
			continue
		}
		found[target.action] = true
		hit, ok := m.dashboardHitAt(layout, target.rect.x+target.rect.w/2, target.rect.y)
		if !ok || hit.kind != "shortcut" || hit.action != target.action {
			t.Fatalf("status action %q resolved to %s, %t", target.action, hit.String(), ok)
		}
	}
	for _, action := range []string{"enter", "s", "e", "i", "d"} {
		if !found[action] {
			t.Fatalf("rendered status bar has no %q target", action)
		}
	}
}

func TestCardActionHitTargetsMatchVisibleLabels(t *testing.T) {
	m := modernDashboardTestModel()
	m.page = tuiSandboxesPage
	m.width = 70 // card fallback rather than master-detail
	m.cursor = 0
	layout := m.dashboardLayout()
	card := layout.cardRect(0, m.scrollRow)
	actions := sandboxCardActionRects(card, m.sandboxes[0])
	if len(actions) != 4 {
		t.Fatalf("running card actions = %d, want 4", len(actions))
	}
	for _, action := range actions {
		hit, ok := m.dashboardHitAt(layout, action.rect.x+action.rect.w/2, action.rect.y)
		if !ok || hit.kind != "entry-action" || hit.action != action.action {
			t.Fatalf("visible %s action resolved to %#v, %t", action.action, hit, ok)
		}
	}
	if gapX := actions[0].rect.x + actions[0].rect.w; gapX < actions[1].rect.x {
		hit, ok := m.dashboardHitAt(layout, gapX, actions[0].rect.y)
		if !ok || hit.kind != "entry" {
			t.Fatalf("space between actions resolved to %s, %t", hit.String(), ok)
		}
	}
}

func TestCreateDialogButtonsUseRenderedBounds(t *testing.T) {
	m := modernDashboardTestModel()
	m.openCreateDialog()
	m.focusCreate(10)
	bounds := m.dialogBounds(tuiCreateDialog)
	cancel, ok := m.dialogButtonRect(bounds, "Cancel")
	if !ok {
		t.Fatal("rendered Cancel button has no hit target")
	}
	model, cmd := m.updateMouseClick(tea.Mouse{X: cancel.x + cancel.w/2, Y: cancel.y, Button: tea.MouseLeft})
	m = *model.(*sandboxTUIModel)
	if cmd != nil || m.dialog != tuiNoDialog {
		t.Fatalf("Cancel click = dialog %d cmd=%v", m.dialog, cmd)
	}
}

func TestCreateDialogSectionHeadingsAreNotClickTargets(t *testing.T) {
	m := modernDashboardTestModel()
	m.openCreateDialog()
	controls := []tuiFormControl{
		{label: "Name", focus: 0}, {label: "OCI image", focus: 1}, {label: "Runtime", focus: 2}, {label: "Kernel", focus: 3},
		{label: "SSH", focus: 4}, {label: "Dev Containers", focus: 5}, {label: "CPUs", focus: 6}, {label: "Memory", focus: 7},
		{label: "Persistent disk", focus: 8}, {label: "Process isolation", focus: 9},
	}
	_, _, content, _ := m.dialogMeasured(tuiThemeFor(m.dark), tuiCreateDialog)
	lines := strings.Split(ansi.Strip(content), "\n")
	sectionRow := -1
	for row, line := range lines {
		if strings.TrimSpace(line) == "RUNTIME" {
			sectionRow = row
			break
		}
	}
	if sectionRow < 0 {
		t.Fatal("RUNTIME section not rendered")
	}
	bounds := m.dialogBounds(tuiCreateDialog)
	mouse := tea.Mouse{X: bounds.x + bounds.w/2, Y: bounds.y + 2 + sectionRow - m.dialogScroll, Button: tea.MouseLeft}
	if focus, ok := m.dialogFormControlAt(mouse, bounds, controls); ok {
		t.Fatalf("section heading mapped to form focus %d", focus)
	}
}

func TestMasterDetailResponsiveFallback(t *testing.T) {
	m := modernDashboardTestModel()
	m.page = tuiSandboxesPage
	m.width = 100
	if !m.usesMasterDetail(m.dashboardLayout()) {
		t.Fatal("medium terminal did not use master-detail layout")
	}
	m.width = 70
	if m.usesMasterDetail(m.dashboardLayout()) {
		t.Fatal("narrow terminal did not fall back to cards")
	}
}
