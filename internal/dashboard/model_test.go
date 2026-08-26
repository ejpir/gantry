package dashboard

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	dashboardapi "github.com/ejpir/gantry/internal/dashboard/api"
	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/dashboardsvc"
	"github.com/ejpir/gantry/internal/selfupdate"
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
		Sandboxes:  []dashboardapi.Sandbox{{Name: "dev", Image: "\x1b[31malpine\x1b[0m\nnext"}},
		Mounts:     []dashboardapi.Mount{{Sandbox: "dev", Error: "first\nsecond"}},
		Secrets:    []dashboardapi.Secret{{Sandbox: "dev", Name: "TOKEN\x1b[2J", State: "loaded\nspoof"}},
		MCPServers: []dashboardapi.MCPServer{{Sandbox: "dev", Name: "api\x1b[2J", URL: "https://example.com/mcp\nspoof", Allow: []string{"read_*\x1b[31m"}}},
	}
	sanitizeSnapshot(&snapshot)
	if snapshot.Sandboxes[0].Image != "alpine next" || snapshot.Mounts[0].Error != "first second" || snapshot.Secrets[0].Name != "TOKEN" || snapshot.Secrets[0].State != "loaded spoof" || snapshot.MCPServers[0].Name != "api" || snapshot.MCPServers[0].URL != "https://example.com/mcp spoof" || snapshot.MCPServers[0].Allow[0] != "read_*" {
		t.Fatalf("snapshot was not sanitized: %#v", snapshot)
	}
}

func TestSandboxTUIMCPServerManagementDialogs(t *testing.T) {
	m := newSandboxTUIModel(dashboardsvc.NewDashboardService())
	m.loading = false
	m.page = tuiMCPPage
	m.width, m.height = 100, 42
	m.sandboxes = []tuiSandbox{{Name: "dev", State: tuiStopped}}
	m.mcpServers = []tuiMCPRow{
		{Sandbox: "dev", Name: "fs", Type: "local", Root: "/work", User: "nobody", State: "saved"},
		{Sandbox: "dev", Name: "github", Type: "remote", URL: "https://example.com/mcp", Allow: []string{"*"}, State: "saved"},
	}

	m.mcpCursor = 1
	model, cmd := m.updateKey(tea.KeyPressMsg{Code: 'e'})
	m = *model.(*sandboxTUIModel)
	if cmd == nil || m.dialog != tuiMCPRemoteDialog || !m.mcpEditing || m.mcpName.Value() != "github" || m.mcpURL.Value() != "https://example.com/mcp" {
		t.Fatalf("MCP edit dialog = dialog %v editing %v name %q url %q cmd=%v", m.dialog, m.mcpEditing, m.mcpName.Value(), m.mcpURL.Value(), cmd)
	}
	plain := ansi.Strip(m.renderMCPRemoteDialog(tuiThemeFor(m.dark), 62))
	if !strings.Contains(plain, "Edit Remote MCP Server") || !strings.Contains(plain, "restart") || !strings.Contains(plain, "Allow tool globs") {
		t.Fatalf("MCP remote dialog copy:\n%s", plain)
	}
	m.closeDialog()

	m.mcpCursor = 0
	model, _ = m.updateKey(tea.KeyPressMsg{Code: 'e'})
	m = *model.(*sandboxTUIModel)
	if m.dialog != tuiMCPFilesystemDialog || m.mcpFSRoot.Value() != "/work" || m.mcpFSUser.Value() != "nobody" {
		t.Fatalf("MCP filesystem dialog = dialog %v root %q user %q", m.dialog, m.mcpFSRoot.Value(), m.mcpFSUser.Value())
	}
	m.closeDialog()

	m.mcpCursor = 1
	model, _ = m.updateKey(tea.KeyPressMsg{Code: 'd'})
	m = *model.(*sandboxTUIModel)
	if m.dialog != tuiMCPRemoveDialog {
		t.Fatalf("MCP remove dialog = %v", m.dialog)
	}
	m.closeDialog()

	m.mcpServers = nil
	model, _ = m.updateKey(tea.KeyPressMsg{Code: 'f'})
	m = *model.(*sandboxTUIModel)
	if m.dialog != tuiMCPFilesystemDialog || m.mcpSandbox.Value() != "dev" || m.mcpFSRoot.Value() != "/" || m.mcpFSUser.Value() != "nobody" {
		t.Fatalf("new MCP filesystem dialog = dialog %v target %q root %q user %q", m.dialog, m.mcpSandbox.Value(), m.mcpFSRoot.Value(), m.mcpFSUser.Value())
	}
	m.closeDialog()

	model, _ = m.updateKey(tea.KeyPressMsg{Code: 'a'})
	m = *model.(*sandboxTUIModel)
	if m.dialog != tuiMCPRemoteDialog || m.mcpEditing || m.mcpSandbox.Value() != "dev" {
		t.Fatalf("MCP add dialog = dialog %v editing %v target %q", m.dialog, m.mcpEditing, m.mcpSandbox.Value())
	}
}

func TestMCPRemoteDialogShowsOnlyRelevantAuthFields(t *testing.T) {
	m := newSandboxTUIModel(dashboardsvc.NewDashboardService())
	m.loading = false
	m.width, m.height = 100, 42
	m.sandboxes = []tuiSandbox{{Name: "dev", State: tuiStopped}}
	m.openMCPRemoteDialog(false)
	theme := tuiThemeFor(m.dark)

	assertFields := func(kind string, wants, rejects []string) {
		t.Helper()
		m.mcpAuthKind = kind
		m.syncMCPAuthPresentation()
		plain := ansi.Strip(m.renderMCPRemoteDialog(theme, 62))
		for _, want := range wants {
			if !strings.Contains(plain, want) {
				t.Fatalf("auth %q missing %q:\n%s", kind, want, plain)
			}
		}
		for _, reject := range rejects {
			if strings.Contains(plain, reject) {
				t.Fatalf("auth %q unexpectedly shows %q:\n%s", kind, reject, plain)
			}
		}
	}
	assertFields("", nil, []string{"Secret name", "Custody provider", "Header name", "X-Api-Key", "Secret / provider reference"})
	assertFields("bearer", []string{"Secret name"}, []string{"Custody provider", "Header name", "X-Api-Key"})
	assertFields("custody", []string{"Custody provider", "provider name"}, []string{"Secret name", "Header name", "X-Api-Key"})
	assertFields("header", []string{"Secret name", "Header name", "X-Api-Key"}, []string{"Custody provider"})

	for _, tc := range []struct {
		kind string
		want []int
	}{
		{kind: "", want: []int{6}},
		{kind: "bearer", want: []int{4, 6}},
		{kind: "custody", want: []int{4, 6}},
		{kind: "header", want: []int{4, 5, 6}},
	} {
		m.mcpAuthKind = tc.kind
		m.focusMCPRemote(3)
		for _, want := range tc.want {
			m.moveMCPRemoteFocus(1)
			if m.mcpFocus != want {
				t.Fatalf("auth %q next focus = %d, want %d", tc.kind, m.mcpFocus, want)
			}
		}
	}
}

func TestDialogTextInputCentersAreClickable(t *testing.T) {
	cases := []struct {
		name, label string
		want        int
		open        func(*sandboxTUIModel)
		focus       func(sandboxTUIModel) int
	}{
		{name: "create image", label: "OCI image", want: 1, open: func(m *sandboxTUIModel) { m.openCreateDialog() }, focus: func(m sandboxTUIModel) int { return m.createFocus }},
		{name: "share tag", label: "Tag", want: 1, open: func(m *sandboxTUIModel) { m.openShareAddDialog(false) }, focus: func(m sandboxTUIModel) int { return m.shareFocus }},
		{name: "port bind", label: "Host bind", want: 1, open: func(m *sandboxTUIModel) { m.openPortPublishDialog() }, focus: func(m sandboxTUIModel) int { return m.portFocus }},
		{name: "policy file", label: "Policy file", want: 1, open: func(m *sandboxTUIModel) { m.openNetworkPolicyDialog() }, focus: func(m sandboxTUIModel) int { return m.policyFocus }},
		{name: "rule destination", label: "Destination", want: 2, open: func(m *sandboxTUIModel) { m.openRuleAddDialog() }, focus: func(m sandboxTUIModel) int { return m.ruleFocus }},
		{name: "secret name", label: "Name", want: 1, open: func(m *sandboxTUIModel) { m.openSecretAddDialog() }, focus: func(m sandboxTUIModel) int { return m.secretFocus }},
		{name: "MCP name", label: "Name", want: 1, open: func(m *sandboxTUIModel) { m.openMCPRemoteDialog(false) }, focus: func(m sandboxTUIModel) int { return m.mcpFocus }},
		{name: "MCP guest root", label: "Guest root", want: 1, open: func(m *sandboxTUIModel) { m.openMCPFilesystemDialog() }, focus: func(m sandboxTUIModel) int { return m.mcpFSFocus }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := newSandboxTUIModel(dashboardsvc.NewDashboardService())
			m.loading = false
			m.width, m.height = 100, 42
			m.sandboxes = []tuiSandbox{{Name: "dev", State: tuiRunning, Net: true}}
			tc.open(&m)
			if m.dialog == tuiNoDialog {
				t.Fatal("form did not open")
			}

			_, _, content, _ := m.dialogMeasured(tuiThemeFor(m.dark), m.dialog)
			lines := strings.Split(ansi.Strip(content), "\n")
			inputTop := -1
			for row, line := range lines {
				if !strings.HasPrefix(strings.TrimSpace(line), tc.label) {
					continue
				}
				for candidate := row + 1; candidate < len(lines); candidate++ {
					if strings.Contains(lines[candidate], "╭") {
						inputTop = candidate
						break
					}
				}
				break
			}
			if inputTop < 0 {
				t.Fatalf("input for %q not found:\n%s", tc.label, ansi.Strip(content))
			}
			bounds := m.dialogBounds(m.dialog)
			// inputTop+1 is the middle row containing the editable value, not
			// either rounded border row.
			mouse := tea.Mouse{
				X:      bounds.x + bounds.w/2,
				Y:      bounds.y + 2 + inputTop + 1 - m.dialogScroll,
				Button: tea.MouseLeft,
			}
			if !bounds.contains(mouse.X, mouse.Y) {
				t.Fatalf("input center for %q is outside dialog: mouse=%v bounds=%v", tc.label, mouse, bounds)
			}
			model, _ := m.updateMouseClick(mouse)
			m = *model.(*sandboxTUIModel)
			if got := tc.focus(m); got != tc.want {
				t.Fatalf("clicking the middle of %q focused %d, want %d", tc.label, got, tc.want)
			}
		})
	}
}

func TestDialogSandboxPickerOptionsAreClickable(t *testing.T) {
	m := newSandboxTUIModel(dashboardsvc.NewDashboardService())
	m.loading = false
	m.width, m.height = 100, 42
	m.sandboxes = []tuiSandbox{
		{Name: "dev", State: tuiStopped},
		{Name: "other", State: tuiStopped},
	}
	m.mcpServers = []tuiMCPRow{
		{Sandbox: "dev", Name: "fs", Type: "local", Root: "/dev-root", User: "nobody"},
		{Sandbox: "other", Name: "fs", Type: "local", Root: "/other-root", User: "65534:65534"},
	}
	m.openMCPFilesystemDialog()
	bounds := m.dialogBounds(m.dialog)

	_, _, content, _ := m.dialogMeasured(tuiThemeFor(m.dark), m.dialog)
	lines := strings.Split(ansi.Strip(content), "\n")
	sandboxRow := -1
	for row, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "Sandbox") {
			sandboxRow = row
			break
		}
	}
	if sandboxRow < 0 {
		t.Fatalf("sandbox picker not rendered:\n%s", ansi.Strip(content))
	}
	model, _ := m.updateMouseClick(tea.Mouse{
		X: bounds.x + bounds.w/2, Y: bounds.y + 2 + sandboxRow + 2, Button: tea.MouseLeft,
	})
	m = *model.(*sandboxTUIModel)
	if !m.mcpSandbox.open {
		t.Fatal("clicking the picker value did not open its menu")
	}

	_, _, content, _ = m.dialogMeasured(tuiThemeFor(m.dark), m.dialog)
	lines = strings.Split(ansi.Strip(content), "\n")
	optionRow := -1
	for row, line := range lines {
		if strings.Contains(line, "other") {
			optionRow = row
			break
		}
	}
	if optionRow < 0 {
		t.Fatalf("picker option not rendered:\n%s", ansi.Strip(content))
	}
	bounds = m.dialogBounds(m.dialog)
	model, _ = m.updateMouseClick(tea.Mouse{
		X: bounds.x + bounds.w/2, Y: bounds.y + 2 + optionRow - m.dialogScroll, Button: tea.MouseLeft,
	})
	m = *model.(*sandboxTUIModel)
	if m.mcpSandbox.open || m.mcpSandbox.Value() != "other" || m.mcpFSRoot.Value() != "/other-root" || m.mcpFSUser.Value() != "65534:65534" {
		t.Fatalf("picker click = open=%t sandbox=%q root=%q user=%q", m.mcpSandbox.open, m.mcpSandbox.Value(), m.mcpFSRoot.Value(), m.mcpFSUser.Value())
	}
}

func TestSandboxTUIShareDialogActions(t *testing.T) {
	m := newSandboxTUIModel(dashboardsvc.NewDashboardService())
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
	_ = newTestConfigStore(t, sandboxDir("stopped"), config.RunConfig{RW: true})

	m := newSandboxTUIModel(dashboardsvc.NewDashboardService())
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
	m := newSandboxTUIModel(dashboardsvc.NewDashboardService())
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
	_ = newTestConfigStore(t, sandboxDir("stopped"), config.RunConfig{Shares: []string{"code=" + host + ",ro"}})

	m := newSandboxTUIModel(dashboardsvc.NewDashboardService())
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
	m := newSandboxTUIModel(dashboardsvc.NewDashboardService())
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

	m := newSandboxTUIModel(dashboardsvc.NewDashboardService())
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
	m := newSandboxTUIModel(dashboardsvc.NewDashboardService())
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
	m := newSandboxTUIModel(dashboardsvc.NewDashboardService())
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
	m := newSandboxTUIModel(dashboardsvc.NewDashboardService())
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
	for _, want := range []string{"GANTRY", "SANDBOXES", "TRAFFIC", "RULES", "MOUNTS", "PORTS", "SECRETS", "dev", "RUNNING", "alpine:latest", "New Sandbox"} {
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
		m := newSandboxTUIModel(dashboardsvc.NewDashboardService())
		m.loading = false
		m.refreshing = false
		m.width, m.height = size[0], size[1]
		m.resizeInputs()
		m.sandboxes = []tuiSandbox{{Name: "dev", State: tuiStopped, Image: "alpine:latest"}}
		m.traffic = []tuiTrafficRow{{Sandbox: "dev", Host: "example.com", Address: "93.184.216.34", Protocol: "tcp", Port: 443, Allowed: true}}
		m.rules = []tuiRuleRow{{Sandbox: "dev", Action: "allow", Target: "public internet", Proto: "any"}}
		m.mounts = []tuiMountRow{{Sandbox: "dev", Tag: "code", Host: "/tmp/code", Guest: "/workspace"}}
		m.ports = []tuiPortRow{{Sandbox: "dev", Bind: "127.0.0.1:8080", Guest: 80, Proto: "tcp", State: "bound"}}
		m.secrets = []tuiSecretRow{{Sandbox: "dev", Name: "TOKEN", State: "required next start"}}
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
	m := newSandboxTUIModel(dashboardsvc.NewDashboardService())
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

func TestSandboxTUICardAndDetailsShowStorageAndOperationalMetadata(t *testing.T) {
	m := newSandboxTUIModel(dashboardsvc.NewDashboardService())
	m.loading = false
	m.width, m.height = 100, 42
	m.sandboxes = []tuiSandbox{{
		Name: "dev", State: tuiRunning, PID: 42, Image: "alpine:latest", Runtime: "crun",
		Kernel: "/cache/assets/v0.0.6/gantry-kernel-arm64", MemMB: 1024, VCPUs: 2,
		RW: true, RWLayer: "/data/dev.ext4", DiskSizeMiB: 2048,
		Net: true, NetPolicy: "/policies/locked.json", AllowLocal: false,
		Shares: 1, Ports: 2, Secrets: "TOKEN", ConfigPath: "/sandboxes/dev/sandbox.json",
	}}
	theme := tuiThemeFor(m.dark)
	card := ansi.Strip(m.renderSandboxCard(theme, m.dashboardLayout(), m.sandboxes[0], true))
	for _, want := range []string{"storage", "2GB", "persistent"} {
		if !strings.Contains(card, want) {
			t.Fatalf("card missing %q:\n%s", want, card)
		}
	}
	details := ansi.Strip(m.renderInfoDialog(theme, 68))
	for _, want := range []string{
		"gantry-kernel-arm64", "2GiB persistent ext4", "Published", "2 ports",
		"Local access", "blocked", "locked.json", "Kernel asset", "/data/dev.ext4",
	} {
		if !strings.Contains(details, want) {
			t.Fatalf("details missing %q:\n%s", want, details)
		}
	}
}

func TestSandboxTUITableNavigationKeepsSelectionVisible(t *testing.T) {
	m := newSandboxTUIModel(dashboardsvc.NewDashboardService())
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

func TestSandboxTUITrafficSelectionSurvivesDNSRefresh(t *testing.T) {
	m := newSandboxTUIModel(dashboardsvc.NewDashboardService())
	m.loading = false
	m.page = tuiTrafficPage
	m.traffic = []tuiTrafficRow{
		{Sandbox: "dev", Host: "api.example.com", Address: "192.168.127.1", Protocol: "dns", Port: 53, Allowed: true},
		{Sandbox: "dev", Host: "cdn.example.com", Address: "192.168.127.1", Protocol: "dns", Port: 53, Allowed: true},
	}
	m.trafficCursor = 0

	_, _ = m.handleRefresh(tuiRefreshMsg{
		at: time.Now(),
		traffic: []tuiTrafficRow{
			{Sandbox: "dev", Host: "cdn.example.com", Address: "192.168.127.1", Protocol: "dns", Port: 53, Allowed: true},
			{Sandbox: "dev", Host: "api.example.com", Address: "192.168.127.1", Protocol: "dns", Port: 53, Allowed: true},
		},
	})
	if selected := m.selectedTraffic(); selected == nil || selected.Host != "api.example.com" {
		t.Fatalf("traffic selection after refresh = %#v, want api.example.com", selected)
	}
}

func TestSandboxTUIBlockedDNSAddsQueriedDomain(t *testing.T) {
	m := newSandboxTUIModel(dashboardsvc.NewDashboardService())
	m.loading = false
	m.page = tuiTrafficPage
	m.sandboxes = []tuiSandbox{{Name: "dev", State: tuiRunning, Net: true}}
	m.traffic = []tuiTrafficRow{{
		Sandbox: "dev", Host: "pi.dev", Address: "192.168.127.1", Protocol: "dns", Port: 53, Allowed: false,
	}}

	model, _ := m.updateKey(tea.KeyPressMsg{Code: 'a'})
	m = *model.(*sandboxTUIModel)
	if m.dialog != tuiRuleAddDialog || m.ruleAction != "allow" || m.ruleProtocol != "dns" || m.ruleTarget.Value() != "pi.dev" || m.rulePorts.Value() != "" {
		t.Fatalf("DNS allowlist form = dialog %d action %q proto %q target %q ports %q", m.dialog, m.ruleAction, m.ruleProtocol, m.ruleTarget.Value(), m.rulePorts.Value())
	}
	plain := ansi.Strip(m.View().Content)
	if !strings.Contains(plain, "DNS Allowlist") || !strings.Contains(plain, "allowDomains") {
		t.Fatalf("DNS allowlist form is not explicit:\n%s", plain)
	}
	bounds := m.dialogBounds(tuiRuleAddDialog)
	button, ok := m.dialogButtonRect(bounds, "Allow domain")
	if !ok {
		t.Fatal("rendered Allow domain button not found")
	}
	model, cmd := m.updateMouseClick(tea.Mouse{X: button.x + button.w/2, Y: button.y, Button: tea.MouseLeft})
	m = *model.(*sandboxTUIModel)
	if cmd == nil || m.dialog != tuiNoDialog || m.busyAction != "rule add" {
		t.Fatalf("Allow domain click = dialog %d action %q cmd=%v", m.dialog, m.busyAction, cmd)
	}

	m.busyAction = ""
	m.traffic[0].Allowed = true
	model, cmd = m.updateKey(tea.KeyPressMsg{Code: 'a'})
	m = *model.(*sandboxTUIModel)
	if cmd == nil || m.dialog != tuiNoDialog || m.toast == nil || m.toast.title != "DNS already allowed" {
		t.Fatalf("allowed DNS action = dialog %d toast=%#v cmd=%v", m.dialog, m.toast, cmd)
	}
}

func TestSandboxTUIUpdateBadgeAndConfirmation(t *testing.T) {
	m := newSandboxTUIModel(dashboardsvc.NewDashboardService())
	m.loading = false
	m.width, m.height = 100, 30
	m.updateStatus = selfupdate.Status{Current: "v1.2.3", Latest: "v1.3.0", Available: true}

	menu := ansi.Strip(m.renderMenuBar(tuiThemeFor(true), m.width))
	if !strings.Contains(menu, "U ↑ v1.3.0") {
		t.Fatalf("update badge missing:\n%s", menu)
	}
	rect := m.menuItemRects(m.width)["update"]
	model, cmd := m.updateMouseClick(tea.Mouse{X: rect.x + rect.w/2, Y: rect.y, Button: tea.MouseLeft})
	m = *model.(*sandboxTUIModel)
	if cmd != nil || m.dialog != tuiUpdateDialog {
		t.Fatalf("badge click = dialog %d cmd=%v", m.dialog, cmd)
	}

	bounds := m.dialogBounds(tuiUpdateDialog)
	cancel, ok := m.dialogButtonRect(bounds, "Cancel")
	if !ok {
		t.Fatal("update Cancel button not found")
	}
	model, cmd = m.updateMouseClick(tea.Mouse{X: cancel.x + cancel.w/2, Y: cancel.y, Button: tea.MouseLeft})
	m = *model.(*sandboxTUIModel)
	if cmd != nil || m.dialog != tuiNoDialog {
		t.Fatalf("update cancel = dialog %d cmd=%v", m.dialog, cmd)
	}

	model, _ = m.updateKey(tea.KeyPressMsg{Code: 'U'})
	m = *model.(*sandboxTUIModel)
	if m.dialog != tuiUpdateDialog {
		t.Fatalf("U opened dialog %d", m.dialog)
	}
	bounds = m.dialogBounds(tuiUpdateDialog)
	update, ok := m.dialogButtonRect(bounds, "Update")
	if !ok {
		t.Fatal("update button not found")
	}
	model, cmd = m.updateMouseClick(tea.Mouse{X: update.x + update.w/2, Y: update.y, Button: tea.MouseLeft})
	m = *model.(*sandboxTUIModel)
	if cmd == nil || m.dialog != tuiNoDialog || m.busyAction != "update" || m.busyName != "v1.3.0" {
		t.Fatalf("update click = dialog %d action=%q name=%q cmd=%v", m.dialog, m.busyAction, m.busyName, cmd)
	}
}

func TestSandboxTUIQuitsAfterSuccessfulUpdate(t *testing.T) {
	m := newSandboxTUIModel(dashboardsvc.NewDashboardService())
	m.updateStatus = selfupdate.Status{Current: "v1.2.3", Latest: "v1.3.0", Available: true}
	m.busyAction = "update"
	model, cmd := m.handleProcessDone(tuiProcessDoneMsg{action: "update", name: "v1.3.0", output: "updated Gantry v1.2.3 → v1.3.0"})
	m = *model.(*sandboxTUIModel)
	if cmd == nil {
		t.Fatal("successful update did not quit")
	}
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Fatalf("successful update command = %T, want tea.QuitMsg", cmd())
	}
	if m.exitMessage == "" || m.updateStatus.Available {
		t.Fatalf("post-update state = message %q status %+v", m.exitMessage, m.updateStatus)
	}
}

func TestCompactCommandErrorPrefersDiagnosticOverProgress(t *testing.T) {
	output := strings.Join([]string{
		"downloading gantry-darwin-arm64 [==============······]  74%",
		"downloading gantry-darwin-arm64 [==================··]  93%",
		"downloading gantry-darwin-arm64 [====================] 100%",
		"gantry update: verify gantry-darwin-arm64: release binary lacks an enabled com.apple.security.hypervisor entitlement",
	}, "\n")

	got := compactCommandError(output, errors.New("exit status 1"))
	if strings.Contains(got, "downloading ") {
		t.Fatalf("error retained progress output: %q", got)
	}
	for _, want := range []string{"lacks an enabled", "exit status 1"} {
		if !strings.Contains(got, want) {
			t.Fatalf("error %q does not contain %q", got, want)
		}
	}
}

func TestSandboxTUIRuleRemovalDistinguishesEntriesFromPosture(t *testing.T) {
	m := newSandboxTUIModel(dashboardsvc.NewDashboardService())
	m.loading = false
	m.page = tuiRulesPage
	m.rules = []tuiRuleRow{{Sandbox: "dev", Target: "example.com", Source: "domain"}}

	model, cmd := m.updateKey(tea.KeyPressMsg{Code: 'd'})
	m = *model.(*sandboxTUIModel)
	if cmd != nil || m.dialog != tuiRuleRemoveDialog {
		t.Fatalf("domain removal = dialog %d cmd=%v", m.dialog, cmd)
	}

	m.closeDialog()
	m.rules = []tuiRuleRow{{Sandbox: "dev", Target: "public internet", Source: "default"}}
	model, cmd = m.updateKey(tea.KeyPressMsg{Code: 'd'})
	m = *model.(*sandboxTUIModel)
	if cmd == nil || m.dialog != tuiNoDialog || m.toast == nil || m.toast.title != "Effective rule" {
		t.Fatalf("default removal feedback = dialog %d toast=%#v cmd=%v", m.dialog, m.toast, cmd)
	}
}

func TestSandboxTUIKeepsCreateSelectionAcrossStaleRefresh(t *testing.T) {
	m := newSandboxTUIModel(dashboardsvc.NewDashboardService())
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

func TestSandboxTUIStreamsDownloadProgress(t *testing.T) {
	events := make(chan tuiProcessStreamEvent, 1)
	output := &tuiProcessOutput{events: events}
	line := "gantry start: downloading gantry-kernel-x86_64 [==========··········]  50% (8.0 MiB/16.0 MiB)"
	if _, err := output.Write([]byte(line + "\nordinary diagnostic\n")); err != nil {
		t.Fatal(err)
	}
	event := <-events
	if event.progress != strings.TrimPrefix(line, "gantry start: ") {
		t.Fatalf("streamed progress = %q", event.progress)
	}
	if got := output.String(); !strings.Contains(got, "ordinary diagnostic") {
		t.Fatalf("captured output lost diagnostics: %q", got)
	}

	m := newSandboxTUIModel(dashboardsvc.NewDashboardService())
	m.loading = false
	m.busyAction = "create"
	m.busyName = "dev"
	m.busyProgress = event.progress
	plain := ansi.Strip(m.View().Content)
	if !strings.Contains(plain, "50%") || !strings.Contains(plain, "gantry-kernel-x86_64") {
		t.Fatalf("dashboard does not render download progress:\n%s", plain)
	}
}

func TestSandboxTUIStreamsPersistentDiskProgress(t *testing.T) {
	events := make(chan tuiProcessStreamEvent, 1)
	output := &tuiProcessOutput{events: events}
	line := "gantry start: creating persistent disk [==========··········]  50% (4096 MiB)"
	if _, err := output.Write([]byte(line + "\n")); err != nil {
		t.Fatal(err)
	}
	if event := <-events; event.progress != strings.TrimPrefix(line, "gantry start: ") {
		t.Fatalf("streamed progress = %q", event.progress)
	}
}

func TestSandboxTUITrafficRulesSupportEveryProtocolPosture(t *testing.T) {
	m := newSandboxTUIModel(dashboardsvc.NewDashboardService())
	m.loading = false
	m.page = tuiTrafficPage
	m.sandboxes = []tuiSandbox{{Name: "dev", State: tuiRunning, Net: true}}
	m.traffic = []tuiTrafficRow{{
		Sandbox: "dev", Address: "203.0.113.9", Protocol: "icmp", Allowed: true,
	}}

	model, _ := m.updateKey(tea.KeyPressMsg{Code: 'a'})
	m = *model.(*sandboxTUIModel)
	if m.dialog != tuiRuleAddDialog || m.ruleAction != "deny" || m.ruleProtocol != "icmp" || m.ruleTarget.Value() != "203.0.113.9" || m.rulePorts.Value() != "" {
		t.Fatalf("ICMP traffic rule form = dialog %d action %q proto %q target %q ports %q", m.dialog, m.ruleAction, m.ruleProtocol, m.ruleTarget.Value(), m.rulePorts.Value())
	}

	m.ruleFocus = 3
	_, _ = m.updateRuleAddDialogKey(tea.KeyPressMsg{Code: tea.KeyRight})
	if m.ruleProtocol != "any" {
		t.Fatalf("protocol after ICMP = %q, want any", m.ruleProtocol)
	}
	m.closeDialog()
	m.traffic[0].Protocol = "ip"
	m.traffic[0].Allowed = false
	model, _ = m.updateKey(tea.KeyPressMsg{Code: 'a'})
	m = *model.(*sandboxTUIModel)
	if m.ruleAction != "allow" || m.ruleProtocol != "any" {
		t.Fatalf("generic IP traffic rule = action %q proto %q", m.ruleAction, m.ruleProtocol)
	}
	m.closeDialog()
	model, cmd := m.updateKey(tea.KeyPressMsg{Code: 'r'})
	m = *model.(*sandboxTUIModel)
	if cmd == nil || m.busyAction != "rule remove" {
		t.Fatalf("traffic rule removal = busy %q cmd=%v", m.busyAction, cmd)
	}
}

func TestSandboxTUISecretsAreListedAndWriteOnly(t *testing.T) {
	m := newSandboxTUIModel(dashboardsvc.NewDashboardService())
	m.loading = false
	m.page = tuiSecretsPage
	m.sandboxes = []tuiSandbox{{Name: "dev", State: tuiRunning}}
	m.secrets = []tuiSecretRow{{Sandbox: "dev", Name: "API_TOKEN", State: "loaded"}}
	plain := ansi.Strip(m.View().Content)
	if !strings.Contains(plain, "API_TOKEN") || !strings.Contains(plain, "loaded") {
		t.Fatalf("secret list is incomplete:\n%s", plain)
	}

	model, _ := m.updateKey(tea.KeyPressMsg{Code: 'a'})
	m = *model.(*sandboxTUIModel)
	if m.dialog != tuiSecretAddDialog {
		t.Fatalf("secret add dialog = %d", m.dialog)
	}
	m.secretName.SetValue("NEW_TOKEN")
	m.secretValue.SetValue("never-render-this")
	m.focusSecret(2)
	plain = ansi.Strip(m.View().Content)
	if strings.Contains(plain, "never-render-this") || !strings.Contains(plain, "••") {
		t.Fatalf("secret value was not masked:\n%s", plain)
	}
	m.closeDialog()
	if m.secretValue.Value() != "" {
		t.Fatal("closing the secret dialog retained the value")
	}
}

func TestSandboxTUIGridNavigationKeepsSelectionVisible(t *testing.T) {
	m := newSandboxTUIModel(dashboardsvc.NewDashboardService())
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
	m := newSandboxTUIModel(dashboardsvc.NewDashboardService())
	m.loading = false
	m.page = tuiTrafficPage
	m.sandboxes = []tuiSandbox{{Name: "dev", State: tuiRunning, Net: true}}
	plain := ansi.Strip(m.View().Content)
	if !strings.Contains(plain, "Restart required for traffic capture") || !strings.Contains(plain, "dev") {
		t.Fatalf("missing restart guidance:\n%s", plain)
	}
}

func TestSandboxTUICompactHelpKeepsAllSections(t *testing.T) {
	m := newSandboxTUIModel(dashboardsvc.NewDashboardService())
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
	m := newSandboxTUIModel(dashboardsvc.NewDashboardService())
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
	m := newSandboxTUIModel(dashboardsvc.NewDashboardService())
	m.loading = false
	m.openCreateDialog()
	m.createName.SetValue("has space")
	_, _ = m.submitCreate()
	if m.formError == "" || m.busyAction != "" {
		t.Fatalf("invalid create submission: error=%q busy=%q", m.formError, m.busyAction)
	}
	plain := ansi.Strip(m.renderCreateDialog(tuiThemeFor(true), 58))
	nameAt := strings.Index(plain, "\nName\n")
	errorAt := strings.Index(plain, "invalid sandbox name")
	imageAt := strings.Index(plain, "\nOCI image")
	if nameAt < 0 || errorAt <= nameAt || imageAt <= errorAt {
		t.Fatalf("name error is not rendered beside its field:\n%s", plain)
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

	m := newSandboxTUIModel(dashboardsvc.NewDashboardService())
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
	m := newSandboxTUIModel(dashboardsvc.NewDashboardService())
	m.loading = false
	m.openCreateDialog()
	m.createName.SetValue("bigger")
	m.focusCreate(6)
	_, _ = m.updateCreateDialogKey(tea.KeyPressMsg{Code: tea.KeyRight})
	if m.createCPUs.Value != 2 {
		t.Fatalf("CPU slider = %d, want 2", m.createCPUs.Value)
	}
	m.focusCreate(7)
	_, _ = m.updateCreateDialogKey(tea.KeyPressMsg{Code: tea.KeyRight})
	if m.createMemory.Value != 640 {
		t.Fatalf("memory slider = %d, want 640", m.createMemory.Value)
	}
	m.focusCreate(8)
	_, _ = m.updateCreateDialogKey(tea.KeyPressMsg{Code: tea.KeyRight})
	if m.createDisk.Value != 1024 {
		t.Fatalf("disk slider = %d, want 1024", m.createDisk.Value)
	}
	m.focusCreate(9)
	_, _ = m.updateCreateDialogKey(tea.KeyPressMsg{Code: tea.KeyRight})
	if m.createIsolation != "required" {
		t.Fatalf("isolation choice = %q, want required", m.createIsolation)
	}
	argv := strings.Join(m.createArgv("bigger"), " ")
	if !strings.Contains(argv, "-cpus 2") || !strings.Contains(argv, "-mem 640") || !strings.Contains(argv, "-disk-size 1024") || !strings.Contains(argv, "-process-isolation required") {
		t.Fatalf("create argv = %q", argv)
	}
}

func TestSandboxTUICreateDevContainersEnablesSSHAndDefaults(t *testing.T) {
	m := newSandboxTUIModel(dashboardsvc.NewDashboardService())
	m.loading = false
	m.openCreateDialog()
	m.focusCreate(5)
	_, _ = m.updateCreateDialogKey(tea.KeyPressMsg{Code: tea.KeySpace})
	if !m.createSSH || !m.createDevContainers || m.createRuntime != "crun" {
		t.Fatalf("features = ssh:%t devcontainers:%t runtime:%s", m.createSSH, m.createDevContainers, m.createRuntime)
	}
	if m.createCPUs.Value != m.limits.DefaultDevContainersVCPUs ||
		m.createMemory.Value != int(m.limits.DefaultDevContainersMemoryMiB) ||
		m.createDisk.Value != int(m.limits.DefaultDevContainersDiskMiB) {
		t.Fatalf("devcontainer defaults = %d CPU, %d MiB RAM, %d MiB disk", m.createCPUs.Value, m.createMemory.Value, m.createDisk.Value)
	}
	argv := strings.Join(m.createArgv("dev"), " ")
	for _, want := range []string{"-ssh", "-devcontainers", "-cpus", "-mem", "-disk-size"} {
		if !strings.Contains(argv, want) {
			t.Errorf("create argv %q lacks %q", argv, want)
		}
	}
}

func TestSandboxTUIEditResourceSliders(t *testing.T) {
	m := newSandboxTUIModel(dashboardsvc.NewDashboardService())
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
	m.focusEdit(2)
	_, _ = m.updateEditDialogKey(tea.KeyPressMsg{Code: tea.KeyRight})
	if m.editCPUs.Value != 3 {
		t.Fatalf("edited CPU = %d, want 3", m.editCPUs.Value)
	}
	plain := ansi.Strip(m.View().Content)
	for _, want := range []string{"Edit Sandbox", "3 CPU", "2048 MiB", "restart"} {
		if !strings.Contains(plain, want) {
			t.Fatalf("edit dialog missing %q:\n%s", want, plain)
		}
	}
}

func TestSandboxTUIEditSaveButtonHitbox(t *testing.T) {
	m := newSandboxTUIModel(dashboardsvc.NewDashboardService())
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

func TestSandboxTUICreateButtonHitbox(t *testing.T) {
	m := newSandboxTUIModel(dashboardsvc.NewDashboardService())
	m.loading = false
	m.width, m.height = 100, 30
	m.openCreateDialog()
	m.createName.SetValue("click-create")
	m.focusCreate(10)

	plain := ansi.Strip(m.View().Content)
	buttonX, buttonY := -1, -1
	lines := strings.Split(plain, "\n")
	for y := len(lines) - 1; y >= 0; y-- {
		if byteOffset := strings.LastIndex(lines[y], "Create"); byteOffset >= 0 {
			buttonX = lipgloss.Width(lines[y][:byteOffset]) + 1
			buttonY = y
			break
		}
	}
	if buttonX < 0 || buttonY < 0 {
		t.Fatalf("Create button not rendered:\n%s", plain)
	}
	model, _ := m.updateMouseClick(tea.Mouse{X: buttonX, Y: buttonY, Button: tea.MouseLeft})
	m = *model.(*sandboxTUIModel)
	if m.dialog != tuiNoDialog || m.busyAction != "create" || m.busyName != "click-create" {
		t.Fatalf("Create click missed: dialog=%d busy=%q name=%q at %d,%d", m.dialog, m.busyAction, m.busyName, buttonX, buttonY)
	}
}

func TestSandboxTUIFeatureToggleHitboxesUseRenderedRows(t *testing.T) {
	clickControl := func(t *testing.T, m *sandboxTUIModel, label string) *sandboxTUIModel {
		t.Helper()
		plain := ansi.Strip(m.View().Content)
		for y, line := range strings.Split(plain, "\n") {
			marker := "│  " + label
			index := strings.Index(line, marker)
			if index < 0 {
				continue
			}
			x := lipgloss.Width(line[:index+len("│  ")]) + 1
			model, _ := m.updateMouseClick(tea.Mouse{X: x, Y: y, Button: tea.MouseLeft})
			return model.(*sandboxTUIModel)
		}
		t.Fatalf("control %q not rendered:\n%s", label, plain)
		return m
	}

	m := newSandboxTUIModel(dashboardsvc.NewDashboardService())
	m.loading = false
	m.width, m.height = 100, 42
	m.openCreateDialog()
	m = *clickControl(t, &m, "SSH")
	if !m.createSSH || m.createDevContainers {
		t.Fatalf("create SSH click = ssh:%t devcontainers:%t", m.createSSH, m.createDevContainers)
	}
	m = *clickControl(t, &m, "Dev Containers")
	if !m.createSSH || !m.createDevContainers {
		t.Fatalf("create Dev Containers click = ssh:%t devcontainers:%t", m.createSSH, m.createDevContainers)
	}

	m.dialog = tuiNoDialog
	m.sandboxes = []tuiSandbox{{Name: "dev", State: tuiRunning, MemMB: 4096, VCPUs: 2}}
	m.cursor = 0
	m.openEditDialog()
	m = *clickControl(t, &m, "Dev Containers")
	if !m.editSSH || !m.editDevContainers {
		t.Fatalf("edit Dev Containers click = ssh:%t devcontainers:%t", m.editSSH, m.editDevContainers)
	}
	m = *clickControl(t, &m, "SSH")
	if m.editSSH || m.editDevContainers {
		t.Fatalf("edit SSH disable click = ssh:%t devcontainers:%t", m.editSSH, m.editDevContainers)
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

	m := newSandboxTUIModel(dashboardsvc.NewDashboardService())
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
		m := newSandboxTUIModel(dashboardsvc.NewDashboardService())
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

func TestSandboxTUIOversizedDialogScrollsAndFollowsFocus(t *testing.T) {
	m := newSandboxTUIModel(dashboardsvc.NewDashboardService())
	m.loading = false
	m.width, m.height = 100, 20
	m.openCreateDialog()
	theme := tuiThemeFor(m.dark)

	initial := ansi.Strip(m.renderDialog(theme))
	if m.dialogMaxScroll() == 0 || !strings.Contains(initial, "┃") || !strings.Contains(initial, "Name") {
		t.Fatalf("oversized dialog has no initial scroll affordance: max=%d\n%s", m.dialogMaxScroll(), initial)
	}

	m.focusCreate(8)
	disk := ansi.Strip(m.renderDialog(theme))
	if m.dialogScroll == 0 || !strings.Contains(disk, "Persistent disk") || !strings.Contains(disk, "512 MiB") {
		t.Fatalf("disk focus was not scrolled into view: scroll=%d\n%s", m.dialogScroll, disk)
	}

	m.focusCreate(10)
	footer := ansi.Strip(m.renderDialog(theme))
	if !strings.Contains(footer, "Create") || !strings.Contains(footer, "esc cancel") {
		t.Fatalf("dialog footer was not reachable: scroll=%d\n%s", m.dialogScroll, footer)
	}

	m.focusCreate(0)
	if m.dialogScroll != 0 {
		t.Fatalf("returning focus to first field left scroll at %d", m.dialogScroll)
	}
	_, _ = m.updateMouseWheel(tea.Mouse{Button: tea.MouseWheelDown})
	if m.dialogScroll == 0 {
		t.Fatal("mouse wheel did not scroll dialog")
	}
	bounds := m.dialogBounds(tuiCreateDialog)
	_, _ = m.updateMouseClick(tea.Mouse{
		X: bounds.x + bounds.w - 2, Y: bounds.y + bounds.h - 3, Button: tea.MouseLeft,
	})
	if m.dialogScroll != m.dialogMaxScroll() {
		t.Fatalf("scrollbar click = %d, want %d", m.dialogScroll, m.dialogMaxScroll())
	}
}

func TestSandboxTUIDialogFieldsCopyAndPaste(t *testing.T) {
	oldWrite := writeDashboardClipboard
	var copied string
	writeDashboardClipboard = func(value string) error {
		copied = value
		return nil
	}
	t.Cleanup(func() { writeDashboardClipboard = oldWrite })

	m := newSandboxTUIModel(dashboardsvc.NewDashboardService())
	m.loading = false
	m.openCreateDialog()
	model, _ := m.Update(tea.PasteMsg{Content: "pasted-name"})
	m = *model.(*sandboxTUIModel)
	if m.createName.Value() != "pasted-name" {
		t.Fatalf("bracketed paste = %q", m.createName.Value())
	}
	_, cmd := m.updateDialogKey(tea.KeyPressMsg{Code: 'c', Mod: tea.ModCtrl})
	if cmd == nil {
		t.Fatal("copy returned no command")
	}
	msg, ok := cmd().(tuiClipboardMsg)
	if !ok || msg.err != nil || copied != "pasted-name" || msg.label != "sandbox name" {
		t.Fatalf("copy result = %#v, clipboard %q", msg, copied)
	}

	m.sandboxes = []tuiSandbox{{Name: "dev", State: tuiRunning, Image: "alpine:latest", ConfigPath: "/sandboxes/dev/sandbox.json"}}
	m.cursor = 0
	m.dialog = tuiInfoDialog
	_, cmd = m.updateDialogKey(tea.KeyPressMsg{Code: 'c'})
	msg, ok = cmd().(tuiClipboardMsg)
	if !ok || msg.err != nil || !strings.Contains(copied, "Sandbox details") || !strings.Contains(copied, "/sandboxes/dev/sandbox.json") {
		t.Fatalf("copy-all result = %#v, clipboard %q", msg, copied)
	}
}

func TestSandboxTUIFormDialogsKeepFooterAndBorder(t *testing.T) {
	m := newSandboxTUIModel(dashboardsvc.NewDashboardService())
	m.loading = false
	m.width, m.height = 100, 42
	m.sandboxes = []tuiSandbox{{Name: "dev", State: tuiRunning, Net: true}}
	m.cursor = 0

	for _, tc := range []struct {
		name   string
		dialog tuiDialog
		open   func()
	}{
		{name: "create", dialog: tuiCreateDialog, open: func() { m.openCreateDialog(); m.focusCreate(10) }},
		{name: "mount", dialog: tuiShareAddDialog, open: func() { m.openShareAddDialog(false) }},
		{name: "publish port", dialog: tuiPortPublishDialog, open: func() { m.openPortPublishDialog() }},
		{name: "MCP remote", dialog: tuiMCPRemoteDialog, open: func() { m.openMCPRemoteDialog(false); m.focusMCPRemote(mcpRemoteSubmitFocus) }},
		{name: "MCP filesystem", dialog: tuiMCPFilesystemDialog, open: func() { m.openMCPFilesystemDialog() }},
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
	m := newSandboxTUIModel(dashboardsvc.NewDashboardService())
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
	m := newSandboxTUIModel(dashboardsvc.NewDashboardService())
	m.loading = false
	m.width, m.height = 100, 42
	m.sandboxes = []tuiSandbox{{Name: "dev", State: tuiRunning}}
	theme := tuiThemeFor(m.dark)
	for _, tc := range []struct {
		name   string
		render func() string
		labels []string
	}{
		{name: "create", render: func() string { return m.renderCreateDialog(theme, 58) }, labels: []string{"Name", "OCI image", "Runtime", "Kernel", "SSH", "Dev Containers", "CPUs", "Memory", "Persistent disk", "Process isolation"}},
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
	m := newSandboxTUIModel(dashboardsvc.NewDashboardService())
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
	m := newSandboxTUIModel(dashboardsvc.NewDashboardService())
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
	pm, err := config.ParsePortSpec(spec)
	if err != nil || pm.HostIP != "0.0.0.0" || pm.HostPort != 8080 || pm.GuestPort != 80 {
		t.Fatalf("spec %q → %+v (%v)", spec, pm, err)
	}
	m.portBind.SetValue("8080") // bare number = loopback + port
	if spec, err = m.portSpecFromDialog(); err != nil {
		t.Fatal(err)
	}
	pm, _ = config.ParsePortSpec(spec)
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

func newTestConfigStore(t *testing.T, dir string, cfg config.RunConfig) struct{} {
	t.Helper()
	if err := writeTestSandboxConfig(dir, cfg); err != nil {
		t.Fatal(err)
	}
	return struct{}{}
}

func readSandboxConfig(dir string) (config.RunConfig, error) {
	var cfg config.RunConfig
	raw, err := os.ReadFile(filepath.Join(dir, "sandbox.json"))
	if err != nil {
		return cfg, err
	}
	err = json.Unmarshal(raw, &cfg)
	return cfg, err
}

func writeTestSandboxConfig(dir string, cfg config.RunConfig) error {
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
