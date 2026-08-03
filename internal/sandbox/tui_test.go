package sandbox

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"gantry/internal/netpol"

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

func TestLoadTUISandboxes(t *testing.T) {
	t.Setenv("GANTRY_HOME", t.TempDir())
	for _, name := range []string{"zeta", "alpha"} {
		if err := os.MkdirAll(sandboxDir(name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(sandboxDir("alpha"), "sandbox.json"), []byte(`{
		"image":"/cache/alpine.erofs",
		"image_ref":"alpine:latest",
		"runtime":"crun",
		"rw":true,
		"net":true,
		"memMB":768,
		"vcpus":2,
		"shares":["code=/tmp"],
		"secret_names":["TOKEN"]
	}`), 0o600); err != nil {
		t.Fatal(err)
	}
	traffic := netpol.TrafficSnapshot{
		Version: 1, TXBytes: 1200, RXBytes: 3400, DroppedPackets: 2,
		Entries: []netpol.TrafficEntry{{
			Host: "example.com", Address: "93.184.216.34", Protocol: "tcp", Port: 443,
			Allowed: true, TXBytes: 1200, RXBytes: 3400, LastSeen: time.Now(),
		}},
	}
	trafficJSON, err := json.Marshal(traffic)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sandboxDir("alpha"), netpol.TrafficFileName), trafficJSON, 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := loadTUISandboxes()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Name != "alpha" || got[1].Name != "zeta" {
		t.Fatalf("sandboxes = %#v, want alpha then zeta", got)
	}
	alpha := got[0]
	if alpha.Image != "alpine:latest" || !alpha.RW || !alpha.Net || alpha.Secrets != "TOKEN" {
		t.Fatalf("alpha metadata = %#v", alpha)
	}
	if alpha.Runtime != "crun" || alpha.MemMB != 768 || alpha.VCPUs != 2 || alpha.Shares != 1 {
		t.Fatalf("alpha runtime metadata = %#v", alpha)
	}
	if alpha.State != tuiStopped {
		t.Fatalf("alpha state = %q, want stopped", alpha.State)
	}
	if alpha.TXBytes != 1200 || alpha.RXBytes != 3400 || alpha.DroppedPackets != 2 {
		t.Fatalf("alpha traffic totals = %#v", alpha)
	}
	data, err := loadTUIData()
	if err != nil {
		t.Fatal(err)
	}
	if len(data.traffic) != 2 || data.traffic[0].Host != "example.com" || data.traffic[1].Host != "unclassified traffic" || data.traffic[1].Allowed {
		t.Fatalf("traffic rows = %#v", data.traffic)
	}
	if len(data.rules) != 4 || data.rules[0].Target != "IPv6 and non-IPv4 traffic" || data.rules[1].Target != "local networks" || data.rules[2].Target != "public internet" || !data.rules[3].Error {
		t.Fatalf("rule rows = %#v", data.rules)
	}
	if len(data.mounts) != 2 || data.mounts[0].Tag != "code" || data.mounts[0].Guest != "/host/code" || data.mounts[1].Error == "" {
		t.Fatalf("mount rows = %#v", data.mounts)
	}
	if !got[1].ConfigError {
		t.Fatal("missing sandbox.json should be surfaced on the card")
	}
}

func TestLoadTUIMountsUsesLiveHubManifest(t *testing.T) {
	t.Setenv("GANTRY_HOME", t.TempDir())
	name := "live"
	if err := os.MkdirAll(sandboxDir(name), 0o700); err != nil {
		t.Fatal(err)
	}
	manifest := `{
		"version": 2,
		"generation": 3,
		"transport": {"tag":"gantry-shares","vmPath":"/run/mnt/gantry-shares"},
		"shares": [{"tag":"code","path":"/tmp/code","ro":true,"vmPath":"/run/mnt/gantry-shares/code","ctrPath":"/host/code","state":"active"}]
	}`
	if err := os.WriteFile(filepath.Join(sandboxDir(name), "shares.json"), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	rows, live := loadTUIMounts(name, RunConfig{}, true)
	if !live || len(rows) != 1 {
		t.Fatalf("rows=%v live=%v", rows, live)
	}
	row := rows[0]
	if row.Tag != "code" || row.Guest != "/host/code" || row.State != "active" || !row.ReadOnly {
		t.Fatalf("row = %#v", row)
	}
}

func TestSandboxTUIShareDialogActions(t *testing.T) {
	m := newSandboxTUIModel()
	m.loading = false
	m.page = tuiMountsPage
	m.sandboxes = []tuiSandbox{{Name: "dev", State: tuiRunning}}
	m.cursor = 0
	cmd := m.openShareAddDialog(false)
	if cmd == nil || m.dialog != tuiShareAddDialog {
		t.Fatalf("share dialog not open: %v", m.dialog)
	}
	m.shareTag.SetValue("code")
	m.sharePath.SetValue("/tmp/code")
	m.shareRO = true
	model, _ := m.submitShare()
	m = *model.(*sandboxTUIModel)
	if m.busyAction != "share add" || m.busyName != "dev/code" {
		t.Fatalf("busy action = %q %q", m.busyAction, m.busyName)
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

func TestSandboxTUIRendersShareHubMountsAndDialog(t *testing.T) {
	m := newSandboxTUIModel()
	m.loading = false
	m.width, m.height = 110, 32
	m.page = tuiMountsPage
	m.sandboxes = []tuiSandbox{{Name: "dev", State: tuiRunning}}
	m.mounts = []tuiMountRow{{
		Sandbox: "dev", Tag: "code", Host: "/tmp/code",
		VM: "/run/mnt/gantry-shares/code", Guest: "/host/code",
		ReadOnly: true, State: "active",
	}}
	m.dialog = tuiShareAddDialog
	m.shareTag.SetValue("data")
	m.sharePath.SetValue("/tmp/data")
	plain := ansi.Strip(m.View().Content)
	for _, want := range []string{"STATE", "ACTIVE", "/host/code", "Add Live Share", "Host path", "read-only"} {
		if !strings.Contains(plain, want) {
			t.Fatalf("render missing %q:\n%s", want, plain)
		}
	}
}

func TestSandboxTUIRenderFillsTerminal(t *testing.T) {
	m := newSandboxTUIModel()
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
	for _, want := range []string{"GANTRY", "SANDBOXES", "TRAFFIC", "RULES", "MOUNTS", "dev", "RUNNING", "alpine:latest", "New Sandbox"} {
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
		m := newSandboxTUIModel()
		m.loading = false
		m.refreshing = false
		m.width, m.height = size[0], size[1]
		m.resizeInputs()
		m.sandboxes = []tuiSandbox{{Name: "dev", State: tuiStopped, Image: "alpine:latest"}}
		m.traffic = []tuiTrafficRow{{Sandbox: "dev", Host: "example.com", Address: "93.184.216.34", Protocol: "tcp", Port: 443, Allowed: true}}
		m.rules = []tuiRuleRow{{Sandbox: "dev", Action: "allow", Target: "public internet", Proto: "any"}}
		m.mounts = []tuiMountRow{{Sandbox: "dev", Tag: "code", Host: "/tmp/code", Guest: "/workspace"}}
		for page := tuiSandboxesPage; page < tuiPageCount; page++ {
			m.page = page
			for _, dialog := range []tuiDialog{tuiNoDialog, tuiHelpDialog, tuiInfoDialog, tuiRemoveDialog, tuiCreateDialog} {
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
	m := newSandboxTUIModel()
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
	m := newSandboxTUIModel()
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
	m := newSandboxTUIModel()
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
	m := newSandboxTUIModel()
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
	m := newSandboxTUIModel()
	m.loading = false
	m.page = tuiTrafficPage
	m.sandboxes = []tuiSandbox{{Name: "dev", State: tuiRunning, Net: true}}
	plain := ansi.Strip(m.View().Content)
	if !strings.Contains(plain, "Restart required for traffic capture") || !strings.Contains(plain, "dev") {
		t.Fatalf("missing restart guidance:\n%s", plain)
	}
}

func TestSandboxTUICompactHelpKeepsAllSections(t *testing.T) {
	m := newSandboxTUIModel()
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
	m := newSandboxTUIModel()
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
	m := newSandboxTUIModel()
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

	m := newSandboxTUIModel()
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
