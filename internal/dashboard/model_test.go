package dashboard

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	dashboardapi "github.com/ejpir/gantry/internal/dashboard/api"
	sandboxpkg "github.com/ejpir/gantry/internal/sandbox"
	"github.com/ejpir/gantry/internal/shares"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
)

func TestRenderSurfaceRestoresNestedBackground(t *testing.T) {
	foreground := lipgloss.Color("#FFFFFF")
	background := lipgloss.Color("#112233")
	inner := lipgloss.NewStyle().Foreground(lipgloss.Color("#FF0000")).Render("nested") + " gap"
	style := lipgloss.NewStyle().Foreground(foreground).Background(background)
	got := renderSurface(style, foreground, background, inner)

	probe := style.Render(" ")
	prefix := probe[:strings.IndexByte(probe, ' ')]
	if !strings.Contains(got, "\x1b[m"+prefix+" gap") {
		t.Fatalf("surface colors were not restored after nested reset: %q", got)
	}
}

func TestSafeUITextStripsTerminalControls(t *testing.T) {
	if got, want := safeUILine("\x1b[31mred\x1b[0m\nnext\tvalue"), "red next value"; got != want {
		t.Fatalf("safeUILine = %q, want %q", got, want)
	}
	if got, want := safeUIBlock("first\r\n\x1b[2Jsecond"), "first\nsecond"; got != want {
		t.Fatalf("safeUIBlock = %q, want %q", got, want)
	}
}

func TestSanitizeSnapshotCoversServiceData(t *testing.T) {
	snapshot := dashboardapi.Snapshot{
		Sandboxes: []dashboardapi.Sandbox{{Name: "dev", Image: "\x1b[31malpine\x1b[0m\nnext"}},
		Mounts:    []dashboardapi.Mount{{Sandbox: "dev", Error: "first\nsecond"}},
	}
	sanitizeSnapshot(&snapshot)
	if snapshot.Sandboxes[0].Image != "alpine next" || snapshot.Mounts[0].Error != "first second" {
		t.Fatalf("snapshot was not sanitized: %#v", snapshot)
	}
}

func TestSandboxTUIShareDialogActions(t *testing.T) {
	m := newSandboxTUIModel(sandboxpkg.NewDashboardService())
	m.loading = false
	m.page = tuiMountsPage
	m.sandboxes = []tuiSandbox{{Name: "dev", State: tuiRunning}}
	m.cursor = 0
	m.openShareAddDialog(false)
	if m.dialog != tuiShareAddDialog || m.shareSandbox.Value() != "dev" {
		t.Fatalf("share dialog not open: %v", m.dialog)
	}
	m.shareTag.SetValue("code")
	m.sharePath.SetValue("/tmp/code")
	m.shareRO = true
	model, _ := m.submitShare()
	m = *model.(*sandboxTUIModel)
	wantAction := "share add"
	if m.busyAction != wantAction || m.busyName != "dev/code" {
		t.Fatalf("busy action = %q %q, want %q", m.busyAction, m.busyName, wantAction)
	}

	m.dialog = tuiNoDialog
	m.busyAction = ""
	m.mounts = []tuiMountRow{{Sandbox: "dev", Tag: "code", Host: "/tmp/code", Guest: "/host/code", ReadOnly: true}}
	m.mountCursor = 0
	model, _ = m.updateKey(tea.KeyPressMsg{Code: 'r'})
	m = *model.(*sandboxTUIModel)
	if m.dialog != tuiShareAddDialog || !m.shareReplace || m.shareTag.Value() != "code" {
		t.Fatalf("replace dialog state: dialog=%v replace=%v tag=%q", m.dialog, m.shareReplace, m.shareTag.Value())
	}
	model, _ = m.updateKey(tea.KeyPressMsg{Code: tea.KeyEscape})
	m = *model.(*sandboxTUIModel)
	if m.dialog != tuiNoDialog {
		t.Fatalf("dialog did not close: %v", m.dialog)
	}
	model, _ = m.updateKey(tea.KeyPressMsg{Code: 'd'})
	m = *model.(*sandboxTUIModel)
	if m.dialog != tuiShareRemoveDialog {
		t.Fatalf("remove dialog = %v", m.dialog)
	}
}

func TestSandboxTUIShareDialogAllowsStoppedSandbox(t *testing.T) {
	t.Setenv("GANTRY_HOME", t.TempDir())
	if err := os.MkdirAll(sandboxDir("stopped"), 0o700); err != nil {
		t.Fatal(err)
	}
	_ = newTestConfigStore(t, sandboxDir("stopped"), sandboxpkg.RunConfig{RW: true})

	m := newSandboxTUIModel(sandboxpkg.NewDashboardService())
	m.loading = false
	m.animating = true // make submit return the configuration command directly
	m.width, m.height = 100, 42
	m.page = tuiMountsPage
	m.sandboxes = []tuiSandbox{
		{Name: "running", State: tuiRunning},
		{Name: "stopped", State: tuiStopped},
	}
	m.cursor = 1
	m.openShareAddDialog(false)
	if m.dialog != tuiShareAddDialog || m.shareSandbox.Value() != "stopped" {
		t.Fatalf("stopped share target: dialog=%v target=%q", m.dialog, m.shareSandbox.Value())
	}
	if len(m.shareSandbox.options) != 2 {
		t.Fatalf("share targets = %v, want running and stopped", m.shareSandbox.options)
	}
	plain := ansi.Strip(m.renderShareAddDialog(tuiThemeFor(m.dark), 62))
	if !strings.Contains(plain, "Add Share") || !strings.Contains(plain, "next starts") || !strings.Contains(plain, "Save") {
		t.Fatalf("stopped share copy does not explain deferred attachment:\n%s", plain)
	}

	m.shareTag.SetValue("code")
	m.sharePath.SetValue(t.TempDir())
	model, cmd := m.submitShare()
	m = *model.(*sandboxTUIModel)
	if cmd == nil || m.busyAction != "share configure" || m.busyName != "stopped/code" {
		t.Fatalf("stopped share action = %q %q cmd=%v", m.busyAction, m.busyName, cmd)
	}
	done, ok := cmd().(tuiProcessDoneMsg)
	if !ok || done.err != nil || !strings.Contains(done.output, "applies on next start") {
		t.Fatalf("stopped share result = %#v", done)
	}
	cfg, err := readSandboxConfig(sandboxDir("stopped"))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Shares) != 1 {
		t.Fatalf("saved shares = %v", cfg.Shares)
	}
	share, err := shares.ParseSpec(cfg.Shares[0])
	if err != nil || share.Tag != "code" || !share.RO {
		t.Fatalf("saved share = %+v (%v)", share, err)
	}
}

func TestSandboxTUIShareDialogAppliesRunningShareLive(t *testing.T) {
	m := newSandboxTUIModel(sandboxpkg.NewDashboardService())
	m.loading = false
	m.animating = true
	m.width, m.height = 100, 42
	m.page = tuiMountsPage
	m.sandboxes = []tuiSandbox{{Name: "dev", State: tuiRunning}}
	m.openShareAddDialog(false)
	m.shareTag.SetValue("code")
	m.sharePath.SetValue(t.TempDir())

	title, description, button := m.shareDialogCopy()
	if title != "Add Live Share" || button != "Add" || description != "Attach a host directory without restarting the sandbox." {
		t.Fatalf("share copy = %q %q %q", title, description, button)
	}
	model, cmd := m.submitShare()
	m = *model.(*sandboxTUIModel)
	if cmd == nil || m.busyAction != "share add" || m.busyName != "dev/code" {
		t.Fatalf("share action = %q %q cmd=%v", m.busyAction, m.busyName, cmd)
	}
}

func TestSandboxTUIRemovesShareFromStoppedSandbox(t *testing.T) {
	t.Setenv("GANTRY_HOME", t.TempDir())
	if err := os.MkdirAll(sandboxDir("stopped"), 0o700); err != nil {
		t.Fatal(err)
	}
	host := t.TempDir()
	_ = newTestConfigStore(t, sandboxDir("stopped"), sandboxpkg.RunConfig{Shares: []string{"code=" + host + ",ro"}})

	m := newSandboxTUIModel(sandboxpkg.NewDashboardService())
	m.loading = false
	m.animating = true // make removal return the persistence command directly
	m.sandboxes = []tuiSandbox{{Name: "stopped", State: tuiStopped}}
	m.mounts = []tuiMountRow{{
		Sandbox: "stopped", Tag: "code", Host: host, Guest: "/host/code", ReadOnly: true, State: "saved",
	}}
	m.mountCursor = 0
	m.dialog = tuiShareRemoveDialog
	plain := ansi.Strip(m.renderShareRemoveDialog(tuiThemeFor(m.dark), 62))
	if !strings.Contains(plain, "no longer be attached") || !strings.Contains(plain, "next start") {
		t.Fatalf("stopped removal copy does not explain persistence:\n%s", plain)
	}

	model, cmd := m.removeSelectedShare()
	m = *model.(*sandboxTUIModel)
	if cmd == nil || m.dialog != tuiNoDialog || m.busyAction != "share remove" || m.busyName != "stopped/code" {
		t.Fatalf("stopped removal action = dialog %v busy %q %q cmd=%v", m.dialog, m.busyAction, m.busyName, cmd)
	}
	done, ok := cmd().(tuiProcessDoneMsg)
	if !ok || done.err != nil {
		t.Fatalf("stopped removal result = %#v", done)
	}
	cfg, err := readSandboxConfig(sandboxDir("stopped"))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Shares) != 0 {
		t.Fatalf("saved shares after removal = %v", cfg.Shares)
	}
}

func TestSandboxTUIFormsSelectSandboxAndCustomMount(t *testing.T) {
	m := newSandboxTUIModel(sandboxpkg.NewDashboardService())
	m.loading = false
	m.width, m.height = 100, 42
	m.sandboxes = []tuiSandbox{
		{Name: "dev", State: tuiRunning, Net: true},
		{Name: "other", State: tuiRunning, Net: true},
		{Name: "stopped", State: tuiStopped},
	}
	m.cursor = 0
	m.openShareAddDialog(false)
	_, _ = m.updateShareDialogKey(tea.KeyPressMsg{Code: tea.KeyEnter})
	_, _ = m.updateShareDialogKey(tea.KeyPressMsg{Code: tea.KeyDown})
	_, _ = m.updateShareDialogKey(tea.KeyPressMsg{Code: tea.KeyEnter})
	if m.shareSandbox.Value() != "other" || m.shareSandbox.open {
		t.Fatalf("mount picker = %q open=%v", m.shareSandbox.Value(), m.shareSandbox.open)
	}
	m.shareTag.SetValue("workspace")
	m.sharePath.SetValue(t.TempDir())
	m.shareMount.SetValue("/Users/eh04xk")
	plain := ansi.Strip(m.renderShareAddDialog(tuiThemeFor(m.dark), 62))
	if !strings.Contains(plain, "restart") || !strings.Contains(plain, "Save") {
		t.Fatalf("custom mount does not explain restart behavior:\n%s", plain)
	}
	model, cmd := m.submitShare()
	m = *model.(*sandboxTUIModel)
	if cmd == nil || m.busyAction != "share configure" || m.busyName != "other/workspace" {
		t.Fatalf("custom mount action = %q %q cmd=%v", m.busyAction, m.busyName, cmd)
	}

	m.busyAction = ""
	m.dialog = tuiNoDialog
	m.openPortPublishDialog()
	_, _ = m.updatePortDialogKey(tea.KeyPressMsg{Code: tea.KeyRight})
	if m.portSandbox.Value() != "other" {
		t.Fatalf("port picker = %q", m.portSandbox.Value())
	}
	m.portGuest.SetValue("80")
	model, _ = m.submitPort()
	m = *model.(*sandboxTUIModel)
	if m.busyAction != "port publish" || !strings.HasPrefix(m.busyName, "other/") {
		t.Fatalf("port action = %q %q", m.busyAction, m.busyName)
	}
}

func TestSandboxTUINetworkPolicyDialog(t *testing.T) {
	dir := t.TempDir()
	devPolicy := filepath.Join(dir, "dev.json")
	otherPolicy := filepath.Join(dir, "other.json")
	if err := os.WriteFile(devPolicy, []byte(`{"default":"deny"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(otherPolicy, []byte(`{"default":"allow"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	m := newSandboxTUIModel(sandboxpkg.NewDashboardService())
	m.loading = false
	m.width, m.height = 100, 42
	m.page = tuiRulesPage
	m.sandboxes = []tuiSandbox{
		{Name: "dev", State: tuiRunning, Net: true, NetPolicy: devPolicy, AllowLocal: true},
		{Name: "other", State: tuiRunning, Net: true, NetPolicy: otherPolicy},
		{Name: "external", State: tuiRunning, Net: true, GVProxy: "/tmp/gvproxy.sock"},
	}
	m.rules = []tuiRuleRow{{Sandbox: "dev", Action: "deny", Target: "public internet", Proto: "any"}}
	if cmd := m.openNetworkPolicyDialog(); cmd != nil {
		_ = cmd
	}
	if m.dialog != tuiNetworkPolicyDialog || m.policySandbox.Value() != "dev" || m.policyPath.Value() != devPolicy || !m.policyLocal {
		t.Fatalf("initial policy form = dialog %d sandbox %q path %q local %t", m.dialog, m.policySandbox.Value(), m.policyPath.Value(), m.policyLocal)
	}
	if len(m.policySandbox.options) != 2 {
		t.Fatalf("eligible policy sandboxes = %v", m.policySandbox.options)
	}

	// The shared picker changes the target and reloads that sandbox's current
	// values instead of carrying form state across targets.
	_, _ = m.updateNetworkPolicyDialogKey(tea.KeyPressMsg{Code: tea.KeyRight})
	if m.policySandbox.Value() != "other" || m.policyPath.Value() != otherPolicy || m.policyLocal {
		t.Fatalf("selected policy form = sandbox %q path %q local %t", m.policySandbox.Value(), m.policyPath.Value(), m.policyLocal)
	}

	rendered := m.renderDialog(tuiThemeFor(m.dark))
	plain := ansi.Strip(rendered)
	for _, want := range []string{"Network Policy", "Policy file", "Local network override", "Subsequent packets", "Apply", "esc cancel"} {
		if !strings.Contains(plain, want) {
			t.Fatalf("policy dialog missing %q:\n%s", want, plain)
		}
	}
	if got, want := lipgloss.Height(rendered), m.dialogBounds(tuiNetworkPolicyDialog).h; got != want {
		t.Fatalf("policy dialog height = %d, bounds = %d", got, want)
	}
	lines := strings.Split(plain, "\n")
	if last := lines[len(lines)-1]; !strings.Contains(last, "╰") || !strings.Contains(last, "╯") {
		t.Fatalf("policy dialog bottom border was clipped: %q", last)
	}

	bounds := m.dialogBounds(tuiNetworkPolicyDialog)
	buttonX, buttonY := -1, -1
	for row, line := range lines {
		if byteOffset := strings.LastIndex(line, "Apply"); byteOffset >= 0 {
			buttonX = bounds.x + lipgloss.Width(line[:byteOffset]) + 1
			buttonY = bounds.y + row
			break
		}
	}
	if buttonX < 0 || buttonY < 0 {
		t.Fatalf("Apply button not rendered:\n%s", plain)
	}
	model, cmd := m.updateMouseClick(tea.Mouse{X: buttonX, Y: buttonY, Button: tea.MouseLeft})
	m = *model.(*sandboxTUIModel)
	if cmd == nil || m.dialog != tuiNoDialog || m.busyAction != "netpolicy set" || m.busyName != "other" {
		t.Fatalf("policy action = dialog %d busy %q/%q cmd=%v", m.dialog, m.busyAction, m.busyName, cmd)
	}
}

func TestSandboxTUIShareOwner(t *testing.T) {
	uid, gid := uint32(1000), uint32(1001)
	m := newSandboxTUIModel(sandboxpkg.NewDashboardService())
	m.loading = false
	m.page = tuiMountsPage
	m.sandboxes = []tuiSandbox{{Name: "dev", State: tuiRunning, Net: true}}
	m.mounts = []tuiMountRow{{
		Sandbox: "dev", Tag: "code", Host: "/tmp/code", Guest: "/host/code",
		UID: &uid, GID: &gid, State: "active",
	}}
	m.mountCursor = 0
	m.openShareAddDialog(true)
	if got := m.shareOwner.Value(); got != "1000:1001" {
		t.Fatalf("replacement owner = %q", got)
	}
	m.shareOwner.SetValue("bad")
	model, _ := m.submitShare()
	m = *model.(*sandboxTUIModel)
	if m.formError == "" || m.busyAction != "" || m.shareFocus != 4 {
		t.Fatalf("invalid owner: error=%q busy=%q focus=%d", m.formError, m.busyAction, m.shareFocus)
	}
}

func TestSandboxTUIRendersShareHubMountsAndDialog(t *testing.T) {
	m := newSandboxTUIModel(sandboxpkg.NewDashboardService())
	m.loading = false
	m.width, m.height = 110, 32
	m.page = tuiMountsPage
	m.sandboxes = []tuiSandbox{{Name: "dev", State: tuiRunning, Net: true}}
	m.mounts = []tuiMountRow{{
		Sandbox: "dev", Tag: "code", Host: "/tmp/code",
		VM: "/run/mnt/gantry-shares/code", Guest: "/host/code",
		ReadOnly: true, State: "active",
	}}
	m.openShareAddDialog(false)
	m.shareTag.SetValue("data")
	m.sharePath.SetValue("/tmp/data")
	plain := ansi.Strip(m.View().Content)
	shareTitle, _, _ := m.shareDialogCopy()
	for _, want := range []string{"STATE", "ACTIVE", shareTitle, "Sandbox", "Host path", "read-only"} {
		if !strings.Contains(plain, want) {
			t.Fatalf("render missing %q:\n%s", want, plain)
		}
	}
}

func TestSandboxTUIRenderFillsTerminal(t *testing.T) {
	m := newSandboxTUIModel(sandboxpkg.NewDashboardService())
	m.loading = false
	m.refreshing = false
	m.width = 100
	m.height = 30
	m.sandboxes = []tuiSandbox{{
		Name: "dev", State: tuiRunning, PID: 42, Image: "alpine:latest",
		Runtime: "crun", MemMB: 512, VCPUs: 2, Net: true, RW: true,
	}}
	view := m.View()
	plain := ansi.Strip(view.Content)
	for _, want := range []string{"GANTRY", "SANDBOXES", "TRAFFIC", "RULES", "MOUNTS", "PORTS", "dev", "RUNNING", "alpine:latest", "New Sandbox"} {
		if !strings.Contains(plain, want) {
			t.Fatalf("view does not contain %q:\n%s", want, plain)
		}
	}
	if got := lipgloss.Width(view.Content); got != m.width {
		t.Fatalf("view width = %d, want %d", got, m.width)
	}
	if got := lipgloss.Height(view.Content); got != m.height {
		t.Fatalf("view height = %d, want %d", got, m.height)
	}
	if !view.AltScreen || view.MouseMode == 0 || !view.ReportFocus {
		t.Fatalf("full-screen view options not enabled: %#v", view)
	}
}

func TestSandboxTUIRenderSizes(t *testing.T) {
	for _, size := range [][2]int{{40, 12}, {60, 20}, {80, 24}, {100, 30}, {140, 40}} {
		m := newSandboxTUIModel(sandboxpkg.NewDashboardService())
		m.loading = false
		m.refreshing = false
		m.width, m.height = size[0], size[1]
		m.resizeInputs()
		m.sandboxes = []tuiSandbox{{Name: "dev", State: tuiStopped, Image: "alpine:latest"}}
		m.traffic = []tuiTrafficRow{{Sandbox: "dev", Host: "example.com", Address: "93.184.216.34", Protocol: "tcp", Port: 443, Allowed: true}}
		m.rules = []tuiRuleRow{{Sandbox: "dev", Action: "allow", Target: "public internet", Proto: "any"}}
		m.mounts = []tuiMountRow{{Sandbox: "dev", Tag: "code", Host: "/tmp/code", Guest: "/workspace"}}
		m.ports = []tuiPortRow{{Sandbox: "dev", Bind: "127.0.0.1:8080", Guest: 80, Proto: "tcp", State: "bound"}}
		for page := tuiSandboxesPage; page < tuiPageCount; page++ {
			m.page = page
			for _, dialog := range []tuiDialog{tuiNoDialog, tuiHelpDialog, tuiInfoDialog, tuiRemoveDialog, tuiCreateDialog, tuiEditDialog} {
				m.dialog = dialog
				view := m.View().Content
				if got := lipgloss.Width(view); got != m.width {
					t.Errorf("%dx%d page %d dialog %d: width = %d", m.width, m.height, page, dialog, got)
				}
				if got := lipgloss.Height(view); got != m.height {
					t.Errorf("%dx%d page %d dialog %d: height = %d", m.width, m.height, page, dialog, got)
				}
			}
		}
	}
}

func TestSandboxTUIResponsiveGrid(t *testing.T) {
	m := newSandboxTUIModel(sandboxpkg.NewDashboardService())
	m.loading = false
	m.height = 30
	m.sandboxes = []tuiSandbox{{Name: "dev"}}
	for width, wantColumns := range map[int]int{60: 1, 80: 2, 100: 3, 140: 3} {
		m.width = width
		if got := m.dashboardLayout().cols; got != wantColumns {
			t.Errorf("width %d: columns = %d, want %d", width, got, wantColumns)
		}
	}
	m.width = 100
	if got := m.dashboardLayout().visibleRows; got != 2 {
		t.Fatalf("visible rows = %d, want 2", got)
	}
}

func TestSandboxTUITableNavigationKeepsSelectionVisible(t *testing.T) {
	m := newSandboxTUIModel(sandboxpkg.NewDashboardService())
	m.loading = false
	m.width, m.height = 80, 16
	m.page = tuiTrafficPage
	for i := 0; i < 12; i++ {
		m.traffic = append(m.traffic, tuiTrafficRow{Sandbox: "dev", Address: fmt.Sprintf("192.0.2.%d", i), Protocol: "tcp", Port: 443})
	}
	m.moveTableCursor(11)
	if m.trafficCursor != 11 || m.trafficScroll == 0 {
		t.Fatalf("traffic selection = cursor %d scroll %d", m.trafficCursor, m.trafficScroll)
	}
	m.setPage(tuiRulesPage)
	if m.page != tuiRulesPage {
		t.Fatalf("page = %d, want rules", m.page)
	}
}

func TestSandboxTUIKeepsCreateSelectionAcrossStaleRefresh(t *testing.T) {
	m := newSandboxTUIModel(sandboxpkg.NewDashboardService())
	m.loading = false
	m.cursor = 0 // trailing New Sandbox card in an empty dashboard
	m.busyAction = "create"
	m.busyName = "dev"
	m.selectNext = "dev"
	_, _ = m.handleRefresh(tuiRefreshMsg{at: time.Now()})
	if m.selectNext != "dev" {
		t.Fatal("in-flight refresh discarded pending create selection")
	}
	m.busyAction = ""
	_, _ = m.handleRefresh(tuiRefreshMsg{
		at: time.Now(), sandboxes: []tuiSandbox{{Name: "dev", State: tuiStarting}},
	})
	if m.cursor != 0 || m.selectNext != "" {
		t.Fatalf("created sandbox selection = cursor %d pending %q", m.cursor, m.selectNext)
	}
}

func TestSandboxTUIGridNavigationKeepsSelectionVisible(t *testing.T) {
	m := newSandboxTUIModel(sandboxpkg.NewDashboardService())
	m.loading = false
	m.width, m.height = 100, 20 // three columns, one visible row
	for _, name := range []string{"a", "b", "c", "d", "e", "f", "g"} {
		m.sandboxes = append(m.sandboxes, tuiSandbox{Name: name})
	}
	m.setCursor(6)
	if m.scrollRow != 2 {
		t.Fatalf("scroll row = %d, want 2", m.scrollRow)
	}
	m.moveCursor(0, -1)
	if m.cursor != 3 || m.scrollRow != 1 {
		t.Fatalf("after moving up: cursor=%d scroll=%d, want 3/1", m.cursor, m.scrollRow)
	}
}

func TestSandboxTUITrafficExplainsRestartRequirement(t *testing.T) {
	m := newSandboxTUIModel(sandboxpkg.NewDashboardService())
	m.loading = false
	m.page = tuiTrafficPage
	m.sandboxes = []tuiSandbox{{Name: "dev", State: tuiRunning, Net: true}}
	plain := ansi.Strip(m.View().Content)
	if !strings.Contains(plain, "Restart required for traffic capture") || !strings.Contains(plain, "dev") {
		t.Fatalf("missing restart guidance:\n%s", plain)
	}
}

func TestSandboxTUICompactHelpKeepsAllSections(t *testing.T) {
	m := newSandboxTUIModel(sandboxpkg.NewDashboardService())
	m.loading = false
	m.width, m.height = 60, 20
	m.dialog = tuiHelpDialog
	plain := ansi.Strip(m.View().Content)
	for _, want := range []string{"NAVIGATION", "SANDBOX ACTIONS", "APPLICATION"} {
		if !strings.Contains(plain, want) {
			t.Fatalf("compact help does not contain %q:\n%s", want, plain)
		}
	}
}

func TestSandboxTUIDialogsAreLayered(t *testing.T) {
	m := newSandboxTUIModel(sandboxpkg.NewDashboardService())
	m.loading = false
	m.refreshing = false
	m.sandboxes = []tuiSandbox{{Name: "dev", State: tuiStopped}}
	m.dialog = tuiRemoveDialog
	plain := ansi.Strip(m.View().Content)
	for _, want := range []string{"Remove Sandbox", "Sandbox: dev", "This cannot be undone.", "Cancel", "Remove"} {
		if !strings.Contains(plain, want) {
			t.Fatalf("remove dialog does not contain %q:\n%s", want, plain)
		}
	}
}

func TestSandboxTUICreateValidation(t *testing.T) {
	m := newSandboxTUIModel(sandboxpkg.NewDashboardService())
	m.loading = false
	m.openCreateDialog()
	m.createName.SetValue("has space")
	_, _ = m.submitCreate()
	if m.formError == "" || m.busyAction != "" {
		t.Fatalf("invalid create submission: error=%q busy=%q", m.formError, m.busyAction)
	}
}

func TestSandboxTUICreateRuntimeAndKernel(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GANTRY_ARTIFACTS", dir)
	arch := "arm64"
	if runtime.GOARCH == "amd64" {
		arch = "x86_64"
	}
	staged := "gantry-kernel-" + arch
	if err := os.WriteFile(filepath.Join(dir, staged), []byte("k"), 0o644); err != nil {
		t.Fatal(err)
	}
	// kernels for the other arch never appear as choices
	other := "nerdbox-kernel-x86_64"
	if arch == "x86_64" {
		other = "nerdbox-kernel-arm64"
	}
	if err := os.WriteFile(filepath.Join(dir, other), []byte("k"), 0o644); err != nil {
		t.Fatal(err)
	}

	m := newSandboxTUIModel(sandboxpkg.NewDashboardService())
	m.loading = false
	m.openCreateDialog()
	m.createName.SetValue("gvisor-box")

	// defaults: crun + auto → no extra flags
	argv := m.createArgv("gvisor-box")
	if strings.Join(argv, " ") != "start gvisor-box" {
		t.Fatalf("default argv = %v", argv)
	}

	// toggle runtime to runsc
	m.createFocus = 2
	_, _ = m.updateCreateDialogKey(tea.KeyPressMsg{Code: tea.KeySpace})
	if m.createRuntime != "runsc" {
		t.Fatalf("runtime after toggle = %q", m.createRuntime)
	}

	// cycle kernel: auto → staged kernel
	m.createFocus = 3
	_, _ = m.updateCreateDialogKey(tea.KeyPressMsg{Code: tea.KeySpace})
	argv = m.createArgv("gvisor-box")
	joined := strings.Join(argv, " ")
	if !strings.Contains(joined, "-runtime runsc") {
		t.Errorf("argv lacks -runtime runsc: %v", argv)
	}
	if !strings.Contains(joined, "-kernel ") || !strings.Contains(joined, staged) {
		t.Errorf("argv lacks the staged kernel: %v", argv)
	}

	// cycle again: back to auto → no -kernel flag
	_, _ = m.updateCreateDialogKey(tea.KeyPressMsg{Code: tea.KeySpace})
	if k := m.createKernelSelection(); k != "" {
		t.Errorf("kernel selection after full cycle = %q, want auto", k)
	}
}

func TestSandboxTUICreateResourceSliders(t *testing.T) {
	m := newSandboxTUIModel(sandboxpkg.NewDashboardService())
	m.loading = false
	m.openCreateDialog()
	m.createName.SetValue("bigger")
	m.focusCreate(4)
	_, _ = m.updateCreateDialogKey(tea.KeyPressMsg{Code: tea.KeyRight})
	if m.createCPUs.Value != 2 {
		t.Fatalf("CPU slider = %d, want 2", m.createCPUs.Value)
	}
	m.focusCreate(5)
	_, _ = m.updateCreateDialogKey(tea.KeyPressMsg{Code: tea.KeyRight})
	if m.createMemory.Value != 640 {
		t.Fatalf("memory slider = %d, want 640", m.createMemory.Value)
	}
	argv := strings.Join(m.createArgv("bigger"), " ")
	if !strings.Contains(argv, "-cpus 2") || !strings.Contains(argv, "-mem 640") {
		t.Fatalf("create argv = %q", argv)
	}
}

func TestSandboxTUIEditResourceSliders(t *testing.T) {
	m := newSandboxTUIModel(sandboxpkg.NewDashboardService())
	m.loading = false
	m.width, m.height = 100, 30
	m.sandboxes = []tuiSandbox{{Name: "dev", State: tuiRunning, MemMB: 2048, VCPUs: 2}}
	m.cursor = 0
	if cmd := m.openEditDialog(); cmd != nil {
		_ = cmd
	}
	if m.dialog != tuiEditDialog || m.editCPUs.Value != 2 || m.editMemory.Value != 2048 {
		t.Fatalf("edit dialog state: dialog=%d cpu=%d memory=%d", m.dialog, m.editCPUs.Value, m.editMemory.Value)
	}
	_, _ = m.updateEditDialogKey(tea.KeyPressMsg{Code: tea.KeyRight})
	if m.editCPUs.Value != 3 {
		t.Fatalf("edited CPU = %d, want 3", m.editCPUs.Value)
	}
	plain := ansi.Strip(m.View().Content)
	for _, want := range []string{"Edit Sandbox", "3 CPU", "2048 MiB", "Restart"} {
		if !strings.Contains(plain, want) {
			t.Fatalf("edit dialog missing %q:\n%s", want, plain)
		}
	}
}

func TestSandboxTUIEditSaveButtonHitbox(t *testing.T) {
	m := newSandboxTUIModel(sandboxpkg.NewDashboardService())
	m.loading = false
	m.width, m.height = 100, 30
	vcpus := 2
	if runtime.GOOS == "windows" {
		vcpus = 1 // Saving must satisfy WHPX's current single-vCPU limit.
	}
	m.sandboxes = []tuiSandbox{{Name: "dev", State: tuiStopped, MemMB: 2048, VCPUs: vcpus}}
	m.cursor = 0
	m.openEditDialog()

	plain := ansi.Strip(m.View().Content)
	buttonX, buttonY := -1, -1
	for y, line := range strings.Split(plain, "\n") {
		if byteOffset := strings.Index(line, "Save"); byteOffset >= 0 {
			buttonX = lipgloss.Width(line[:byteOffset]) + 1
			buttonY = y
			break
		}
	}
	if buttonX < 0 || buttonY < 0 {
		t.Fatalf("Save button not rendered:\n%s", plain)
	}
	model, _ := m.updateMouseClick(tea.Mouse{X: buttonX, Y: buttonY, Button: tea.MouseLeft})
	m = *model.(*sandboxTUIModel)
	if m.dialog != tuiNoDialog || m.busyAction != "edit" || m.busyName != "dev" {
		t.Fatalf("Save click missed: dialog=%d busy=%q name=%q at %d,%d", m.dialog, m.busyAction, m.busyName, buttonX, buttonY)
	}
}

func TestSandboxTUIMountAndPortButtonHitboxes(t *testing.T) {
	clickLabel := func(t *testing.T, m *sandboxTUIModel, label string) *sandboxTUIModel {
		t.Helper()
		plain := ansi.Strip(m.View().Content)
		lines := strings.Split(plain, "\n")
		for y := len(lines) - 1; y >= 0; y-- {
			if byteOffset := strings.LastIndex(lines[y], label); byteOffset >= 0 {
				x := lipgloss.Width(lines[y][:byteOffset]) + 1
				model, _ := m.updateMouseClick(tea.Mouse{X: x, Y: y, Button: tea.MouseLeft})
				return model.(*sandboxTUIModel)
			}
		}
		t.Fatalf("%q button not rendered:\n%s", label, plain)
		return m
	}

	m := newSandboxTUIModel(sandboxpkg.NewDashboardService())
	m.loading = false
	m.width, m.height = 100, 42
	m.sandboxes = []tuiSandbox{{Name: "dev", State: tuiRunning, Net: true}}
	m.openShareAddDialog(false)
	m.shareTag.SetValue("code")
	m.sharePath.SetValue(t.TempDir())
	_, _, shareButton := m.shareDialogCopy()
	wantAction := "share add"
	m = *clickLabel(t, &m, shareButton)
	if m.busyAction != wantAction || m.busyName != "dev/code" {
		t.Fatalf("%s click missed: busy=%q name=%q", shareButton, m.busyAction, m.busyName)
	}

	m.busyAction = ""
	m.dialog = tuiNoDialog
	m.openPortPublishDialog()
	m.portGuest.SetValue("80")
	m = *clickLabel(t, &m, "Publish")
	if m.busyAction != "port publish" || !strings.HasPrefix(m.busyName, "dev/") {
		t.Fatalf("Publish click missed: busy=%q name=%q", m.busyAction, m.busyName)
	}
}

func TestSandboxTUIEditDialogMatchesOverlayBounds(t *testing.T) {
	for _, size := range [][2]int{{100, 30}, {68, 22}, {60, 20}} {
		m := newSandboxTUIModel(sandboxpkg.NewDashboardService())
		m.loading = false
		m.width, m.height = size[0], size[1]
		m.sandboxes = []tuiSandbox{{
			Name: strings.Repeat("long-name-", 8), State: tuiRunning, MemMB: 7296, VCPUs: 1,
		}}
		m.openEditDialog()
		_, wantHeight := m.dialogSize(tuiEditDialog)
		rendered := m.renderDialog(tuiThemeFor(m.dark))
		if got := lipgloss.Height(rendered); got != wantHeight {
			t.Errorf("%dx%d rendered dialog height = %d, bounds = %d", size[0], size[1], got, wantHeight)
		}
		if got, wantWidth := lipgloss.Width(rendered), m.dialogBounds(tuiEditDialog).w; got != wantWidth {
			t.Errorf("%dx%d rendered dialog width = %d, bounds = %d", size[0], size[1], got, wantWidth)
		}
	}
}

func TestSandboxTUIFormDialogsKeepFooterAndBorder(t *testing.T) {
	m := newSandboxTUIModel(sandboxpkg.NewDashboardService())
	m.loading = false
	m.width, m.height = 100, 42
	m.sandboxes = []tuiSandbox{{Name: "dev", State: tuiRunning, Net: true}}
	m.cursor = 0

	for _, tc := range []struct {
		name   string
		dialog tuiDialog
		open   func()
	}{
		{name: "create", dialog: tuiCreateDialog, open: func() { m.openCreateDialog() }},
		{name: "mount", dialog: tuiShareAddDialog, open: func() { m.openShareAddDialog(false) }},
		{name: "publish port", dialog: tuiPortPublishDialog, open: func() { m.openPortPublishDialog() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.open()
			rendered := m.renderDialog(tuiThemeFor(m.dark))
			_, wantHeight := m.dialogSize(tc.dialog)
			if got := lipgloss.Height(rendered); got != wantHeight {
				t.Fatalf("rendered height = %d, bounds = %d", got, wantHeight)
			}
			plain := ansi.Strip(rendered)
			if !strings.Contains(plain, "esc cancel") {
				t.Fatalf("footer was clipped:\n%s", plain)
			}
			lines := strings.Split(plain, "\n")
			last := lines[len(lines)-1]
			if !strings.Contains(last, "╰") || !strings.Contains(last, "╯") {
				t.Fatalf("bottom border was clipped: %q\n%s", last, plain)
			}
		})
	}
}

func TestSandboxTUIConfirmationDialogsMeasureWrappedContent(t *testing.T) {
	m := newSandboxTUIModel(sandboxpkg.NewDashboardService())
	m.loading = false
	m.width, m.height = 100, 42
	m.mounts = []tuiMountRow{{Sandbox: "codex-dev", Tag: "code", Host: "/Users/eh04xk/repos", Guest: "/host/code"}}
	m.ports = []tuiPortRow{{Sandbox: "codex-dev", Bind: "127.0.0.1:8080", Guest: 80, Proto: "tcp"}}
	theme := tuiThemeFor(m.dark)
	for _, dialog := range []tuiDialog{tuiShareRemoveDialog, tuiPortUnpublishDialog} {
		m.dialog = dialog
		rendered := m.renderDialog(theme)
		plain := ansi.Strip(rendered)
		if !strings.Contains(plain, "enter confirm") {
			t.Fatalf("dialog %d clipped its footer:\n%s", dialog, plain)
		}
		lines := strings.Split(plain, "\n")
		hintRow := -1
		for i, line := range lines {
			if strings.Contains(line, "enter confirm") {
				hintRow = i
				break
			}
		}
		separator := ""
		if hintRow >= 1 {
			separator = strings.TrimSpace(strings.Trim(lines[hintRow-1], "│"))
		}
		if hintRow < 1 || separator != "" {
			t.Fatalf("dialog %d has no separator above keyboard hints:\n%s", dialog, plain)
		}
		last := lines[len(lines)-1]
		if !strings.Contains(last, "╰") || !strings.Contains(last, "╯") {
			t.Fatalf("dialog %d clipped its bottom border:\n%s", dialog, plain)
		}
		if got, want := lipgloss.Height(rendered), m.dialogBounds(dialog).h; got != want {
			t.Fatalf("dialog %d height=%d bounds=%d", dialog, got, want)
		}
	}
}

func TestSandboxTUIFormDialogsUseSpaciousSections(t *testing.T) {
	m := newSandboxTUIModel(sandboxpkg.NewDashboardService())
	m.loading = false
	m.width, m.height = 100, 42
	m.sandboxes = []tuiSandbox{{Name: "dev", State: tuiRunning}}
	theme := tuiThemeFor(m.dark)
	for _, tc := range []struct {
		name   string
		render func() string
		labels []string
	}{
		{name: "create", render: func() string { return m.renderCreateDialog(theme, 58) }, labels: []string{"Name", "OCI image", "Runtime", "Kernel", "CPUs", "Memory"}},
		{name: "mount", render: func() string { return m.renderShareAddDialog(theme, 62) }, labels: []string{"Sandbox", "Tag", "Host path", "Mount point", "Guest owner", "Mode"}},
		{name: "port", render: func() string { return m.renderPortPublishDialog(theme, 62) }, labels: []string{"Host bind", "Guest port", "Protocol"}},
		{name: "policy", render: func() string { return m.renderNetworkPolicyDialog(theme, 62) }, labels: []string{"Sandbox", "Policy file", "Local network override"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plain := ansi.Strip(tc.render())
			for _, next := range tc.labels {
				if !strings.Contains(plain, "\n\n"+next) {
					t.Fatalf("missing section spacing before %q:\n%s", next, plain)
				}
			}
		})
	}
}

func TestSandboxTUIFormFooterSeparatesActionAndHints(t *testing.T) {
	m := newSandboxTUIModel(sandboxpkg.NewDashboardService())
	m.loading = false
	m.width, m.height = 100, 42
	m.sandboxes = []tuiSandbox{{Name: "dev", State: tuiRunning}}
	m.openShareAddDialog(false)
	_, _, shareButton := m.shareDialogCopy()
	theme := tuiThemeFor(m.dark)
	for _, tc := range []struct {
		name, button, hint, rendered string
	}{
		{name: "create", button: "Create", hint: "tab next", rendered: m.renderCreateDialog(theme, 58)},
		{name: "edit", button: "Save", hint: "adjust", rendered: m.renderEditDialog(theme, 58)},
		{name: "mount", button: shareButton, hint: "tab next", rendered: m.renderShareAddDialog(theme, 62)},
		{name: "port", button: "Publish", hint: "tab next", rendered: m.renderPortPublishDialog(theme, 62)},
		{name: "policy", button: "Apply", hint: "tab next", rendered: m.renderNetworkPolicyDialog(theme, 62)},
	} {
		plain := ansi.Strip(tc.rendered)
		lines := strings.Split(plain, "\n")
		hintRow := -1
		for i := len(lines) - 1; i >= 0; i-- {
			if strings.Contains(lines[i], tc.hint) {
				hintRow = i
				break
			}
		}
		if hintRow < 2 || strings.TrimSpace(lines[hintRow-1]) != "" || !strings.Contains(lines[hintRow-2], tc.button) {
			t.Fatalf("%s footer does not separate %q from its hints:\n%s", tc.name, tc.button, plain)
		}
	}
}

func TestResourceSliderMouseAndBounds(t *testing.T) {
	slider := newResourceSlider(1, 8, 1, 1)
	slider.SetFraction(9, 10)
	if slider.Value != 8 {
		t.Fatalf("mouse max = %d, want 8", slider.Value)
	}
	slider.Adjust(1)
	if slider.Value != 8 {
		t.Fatalf("slider escaped max: %d", slider.Value)
	}
	slider.SetFraction(0, 10)
	if slider.Value != 1 {
		t.Fatalf("mouse min = %d, want 1", slider.Value)
	}
}

// Regression: the publish dialog's guest field accepted arbitrary text, so
// "[::]:80" in the guest field composed into an IPv6 wildcard bind despite
// the dialog claiming loopback defaults. Both fields are now strict ports.
func TestPortDialogRejectsSmuggledBind(t *testing.T) {
	m := newSandboxTUIModel(sandboxpkg.NewDashboardService())
	m.loading = false
	m.sandboxes = []tuiSandbox{{Name: "dev", State: tuiRunning}}
	m.portGuest.SetValue("[::]:80")
	if _, err := m.portSpecFromDialog(); err == nil {
		t.Fatal("guest field accepted an address")
	}
	m.portGuest.SetValue("80")
	m.portBind.SetValue("0.0.0.0:8080")
	spec, err := m.portSpecFromDialog()
	if err != nil {
		t.Fatal(err)
	}
	pm, err := sandboxpkg.ParsePortSpec(spec)
	if err != nil || pm.HostIP != "0.0.0.0" || pm.HostPort != 8080 || pm.GuestPort != 80 {
		t.Fatalf("spec %q → %+v (%v)", spec, pm, err)
	}
	m.portBind.SetValue("8080") // bare number = loopback + port
	if spec, err = m.portSpecFromDialog(); err != nil {
		t.Fatal(err)
	}
	pm, _ = sandboxpkg.ParsePortSpec(spec)
	if pm.HostIP != "127.0.0.1" || pm.HostPort != 8080 {
		t.Fatalf("bare bind → %+v", pm)
	}
	m.portBind.SetValue("example.com:8080") // hostnames are not accepted
	if _, err := m.portSpecFromDialog(); err == nil {
		t.Fatal("hostname bind accepted")
	}
}

// bindExposure classifies by parsing: a specific LAN address must not be
// labelled loopback-only.
func TestBindExposureClassification(t *testing.T) {
	cases := map[string]string{
		"127.0.0.1:8080":    "loopback",
		"[::1]:8080":        "loopback",
		"0.0.0.0:8080":      "LAN",
		"[::]:8080":         "LAN",
		"192.168.1.10:8080": "192.168.1.10",
	}
	for bind, want := range cases {
		if got := bindExposure(bind); !strings.Contains(got, want) {
			t.Errorf("bindExposure(%q) = %q, want %q", bind, got, want)
		}
	}
}

func TestSandboxPickerEmptyDoesNotOpen(t *testing.T) {
	// regression: enter/space on a picker with zero options opened an
	// empty bordered menu under a "no running sandbox" field.
	var p sandboxPicker
	p.ResetWhere(nil, "", func(tuiSandbox) bool { return true })
	for _, key := range []string{"enter", " ", "space"} {
		p.HandleKey(key)
		if p.open {
			t.Fatalf("key %q opened an empty picker", key)
		}
		if p.menuHeight() != 0 {
			t.Fatalf("key %q: empty picker must not reserve menu rows", key)
		}
	}
	p.ResetWhere([]tuiSandbox{{Name: "sb", State: tuiRunning}}, "", func(s tuiSandbox) bool { return s.State == tuiRunning })
	p.HandleKey("enter")
	if !p.open {
		t.Fatal("picker with options must open on enter")
	}
}

func sandboxDir(name string) string {
	return filepath.Join(os.Getenv("GANTRY_HOME"), name)
}

func newTestConfigStore(t *testing.T, dir string, cfg sandboxpkg.RunConfig) struct{} {
	t.Helper()
	if err := writeTestSandboxConfig(dir, cfg); err != nil {
		t.Fatal(err)
	}
	return struct{}{}
}

func readSandboxConfig(dir string) (sandboxpkg.RunConfig, error) {
	var cfg sandboxpkg.RunConfig
	raw, err := os.ReadFile(filepath.Join(dir, "sandbox.json"))
	if err != nil {
		return cfg, err
	}
	err = json.Unmarshal(raw, &cfg)
	return cfg, err
}

func writeTestSandboxConfig(dir string, cfg sandboxpkg.RunConfig) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if cfg.MemMB == 0 {
		cfg.MemMB = 512
	}
	if cfg.VCPUs == 0 {
		cfg.VCPUs = 1
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "sandbox.json"), raw, 0o600)
}
