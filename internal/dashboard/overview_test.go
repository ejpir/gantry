package dashboard

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
)

func TestOverviewGroupsDistinctMulticastTargetsWithoutChangingTraffic(t *testing.T) {
	m := modernDashboardTestModel()
	now := time.Now()
	m.traffic = []tuiTrafficRow{
		{Sandbox: "dev", Host: "ff02::2", LastSeen: now.Add(-3 * time.Minute)},
		{Sandbox: "dev", Host: "ff02:0:0:0:0:0:0:2", LastSeen: now.Add(-2 * time.Minute)},
		{Sandbox: "dev", Address: "ff02::16", LastSeen: now.Add(-4 * time.Minute)},
		{Sandbox: "dev", Host: "ff02::1:ffce:ecee", LastSeen: now.Add(-time.Minute)},
		{Sandbox: "dev", Host: "example.test", LastSeen: now},
		{Sandbox: "dev", Host: "example.test", Protocol: "udp", LastSeen: now.Add(-time.Hour)},
		{Sandbox: "dev", Host: "ff02.example.test"},
		{Sandbox: "dev", Host: "224.0.0.1"},
		{Sandbox: "dev", Host: "allowed.test", Allowed: true, LastSeen: now},
		{Sandbox: "other", Host: "other.test", LastSeen: now},
	}
	original := append([]tuiTrafficRow(nil), m.traffic...)
	groups := m.overviewDeniedGroups("dev")
	if len(groups) != 4 || groups[0].label != "example.test" || groups[1].label != "IPv6 multicast ×3 targets" {
		t.Fatalf("unexpected deny groups: %+v", groups)
	}
	if !groups[1].at.Equal(now.Add(-time.Minute)) {
		t.Fatalf("multicast group did not retain its most recent time: %+v", groups[1])
	}
	for i := 0; i < 10; i++ {
		if !reflect.DeepEqual(m.overviewDeniedGroups("dev"), groups) {
			t.Fatal("group order changes when timestamps are equal or unknown")
		}
	}
	for _, dark := range []bool{true, false} {
		text := ansi.Strip(m.recentDeniedHosts(tuiThemeFor(dark), "dev", 2))
		if text != "example.test · IPv6 multicast ×3 targets · +2 more" {
			t.Fatalf("deny summary = %q", text)
		}
		if got := m.recentDeniedHosts(tuiThemeFor(dark), "dev", 0); got != "" {
			t.Fatalf("zero-limit summary = %q", got)
		}
	}
	if !reflect.DeepEqual(m.traffic, original) {
		t.Fatal("overview grouping mutated the full traffic records")
	}
}

func TestOverviewLayoutAndHitTargetsAcrossBreakpoints(t *testing.T) {
	for _, dark := range []bool{true, false} {
		for _, width := range []int{24, 40, 70, 77, 78, 79, 80, 81, 100, 139, 140, 141, 170, 240, 300} {
			for _, height := range []int{7, 12, 24, 29, 30, 40} {
				m := modernDashboardTestModel()
				m.dark, m.width, m.height, m.page = dark, width, height, tuiOverviewPage
				m.sandboxes = append(m.sandboxes, m.sandboxes[0], m.sandboxes[1], m.sandboxes[0])
				m.setCursor(len(m.sandboxes) - 1)
				view := m.View().Content
				if lipgloss.Width(view) != width || lipgloss.Height(view) != height {
					t.Fatalf("dark=%t %dx%d overview rendered %dx%d", dark, width, height, lipgloss.Width(view), lipgloss.Height(view))
				}
				layout := m.dashboardLayout()
				geometry := m.overviewGeometry(layout)
				wantInspector := width >= tuiOverviewInspectorMinWidth && layout.contentHeight >= tuiOverviewInspectorHeight
				if (geometry.inspectorRect.w > 0) != wantInspector {
					t.Fatalf("%dx%d: unexpected inspector geometry %+v", width, height, geometry)
				}
				if _, ok := geometry.entryRects[m.cursor]; !ok {
					t.Fatalf("%dx%d: selected sandbox scrolled out of view", width, height)
				}
				for _, target := range m.dashboardHits {
					r := target.rect
					if r.w < 1 || r.h < 1 || r.x < 0 || r.y < 0 || r.x+r.w > width || r.y+r.h > height {
						t.Fatalf("%dx%d: off-screen mouse target %+v", width, height, target)
					}
					got, ok := m.dashboardHitAt(layout, r.x+r.w/2, r.y+r.h/2)
					if !ok || got != target {
						t.Fatalf("%dx%d: mouse target mismatch %+v -> %+v", width, height, target, got)
					}
				}
				// A long image, host name, or growing counter must not resize the cards.
				m.sandboxes[0].Image = strings.Repeat("long-image-", 40)
				m.sandboxes[0].DroppedPackets = ^uint64(0)
				m.traffic[0].Host = strings.Repeat("long-host.", 40)
				if got := m.overviewGeometry(layout); got.panelWidth != geometry.panelWidth || got.inspectorRect != geometry.inspectorRect {
					t.Fatalf("%dx%d: live data changed layout geometry", width, height)
				}
			}
		}
	}
}

func TestOverviewInspectorFollowsSelectionAndOnlyUsesSelectedData(t *testing.T) {
	m := modernDashboardTestModel()
	m.page = tuiOverviewPage
	m.sandboxes[1].State = tuiStopped
	m.sandboxes[1].Net = true
	m.mounts = []tuiMountRow{
		{Sandbox: "codex-dev", Guest: "/first-project"},
		{Sandbox: "testnick", Guest: "/second-project", ReadOnly: true},
	}
	m.ports = []tuiPortRow{
		{Sandbox: "codex-dev", Bind: "127.0.0.1:8001", Guest: 80, Proto: "tcp", State: "bound"},
		{Sandbox: "testnick", Bind: "127.0.0.1:9002", Guest: 90, Proto: "tcp", State: "saved"},
	}
	readInspector := func() string {
		t.Helper()
		text, _ := m.renderOverviewInspector(tuiThemeFor(m.dark), m.overviewGeometry(m.dashboardLayout()).inspectorRect)
		return ansi.Strip(text)
	}
	first := readInspector()
	if !strings.Contains(first, "/first-project") || !strings.Contains(first, "8001") || strings.Contains(first, "/second-project") {
		t.Fatalf("inspector mixed sandbox data:\n%s", first)
	}
	_, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyDown})
	second := readInspector()
	for _, want := range []string{"testnick", "ro  /second-project", "9002", "saved", "IPv6 multicast ×1 target"} {
		if !strings.Contains(second, want) {
			t.Fatalf("selected inspector missing %q:\n%s", want, second)
		}
	}
	if strings.Contains(second, "/first-project") || strings.Contains(second, "8001") || strings.Contains(second, "debian.org") {
		t.Fatalf("inspector retained previous selection data:\n%s", second)
	}
}

func TestOverviewInspectorActionRowsAreClickable(t *testing.T) {
	for _, action := range []string{"enter", "t", "e", "i"} {
		t.Run(action, func(t *testing.T) {
			m := modernDashboardTestModel()
			m.page = tuiOverviewPage
			view := m.View().Content
			geometry := m.overviewGeometry(m.dashboardLayout())
			plain := strings.Split(ansi.Strip(view), "\n")
			var found *tuiHitTarget
			for _, target := range m.dashboardHits {
				if target.kind == "shortcut" && target.action == action && target.rect.x >= geometry.inspectorRect.x {
					copy := target
					found = &copy
					break
				}
			}
			if found == nil {
				t.Fatalf("no inspector target for %q", action)
			}
			if text := ansi.Cut(plain[found.rect.y], found.rect.x, found.rect.x+found.rect.w); !strings.HasPrefix(text, action) {
				t.Fatalf("target does not match the rendered action: %+v = %q", found, text)
			}
			_, _ = m.updateMouseClick(tea.Mouse{X: found.rect.x + 1, Y: found.rect.y, Button: tea.MouseLeft})
			switch action {
			case "enter":
				if m.page != tuiSandboxesPage {
					t.Fatal("open did not navigate to Sandboxes")
				}
			case "t":
				if m.page != tuiTrafficPage {
					t.Fatal("traffic action did not navigate to Traffic")
				}
			case "e":
				if m.dialog != tuiEditDialog {
					t.Fatal("edit action did not open configuration")
				}
			case "i":
				if m.dialog != tuiInfoDialog {
					t.Fatal("details action did not open details")
				}
			}
		})
	}
}

func TestOverviewInspectorBusyAndOverflowContent(t *testing.T) {
	m := modernDashboardTestModel()
	m.page = tuiOverviewPage
	for i := 0; i < 8; i++ {
		m.mounts = append(m.mounts, tuiMountRow{Sandbox: "codex-dev", Guest: fmt.Sprintf("/long/%d/%s", i, strings.Repeat("path", 30))})
		m.ports = append(m.ports, tuiPortRow{Sandbox: "codex-dev", Bind: fmt.Sprintf("127.0.0.1:%d", 8000+i), Guest: 80, State: "saved"})
	}
	rect := m.overviewGeometry(m.dashboardLayout()).inspectorRect
	text, actions := m.renderOverviewInspector(tuiThemeFor(m.dark), rect)
	if lipgloss.Width(text) != rect.w || lipgloss.Height(text) != rect.h || len(actions) != 4 {
		t.Fatalf("overflowing data displaced inspector actions: %dx%d, %d actions", lipgloss.Width(text), lipgloss.Height(text), len(actions))
	}
	plain := ansi.Strip(text)
	if !strings.Contains(plain, "more · see Mounts") || !strings.Contains(plain, "more · see Ports") {
		t.Fatalf("inspector silently hid overflow:\n%s", plain)
	}
	m.busyAction, m.busyName = "stop", "codex-dev"
	text, actions = m.renderOverviewInspector(tuiThemeFor(m.dark), rect)
	if len(actions) != 0 || !strings.Contains(ansi.Strip(text), "Action in progress") {
		t.Fatal("busy inspector advertises actionable controls")
	}
}

func TestOverviewUnknownMountModesAreNotReportedReadOnly(t *testing.T) {
	m := modernDashboardTestModel()
	m.mounts = nil
	value, note := m.overviewAccess(tuiThemeFor(true), m.sandboxes[0])
	if !strings.Contains(ansi.Strip(value), "4 mounts") || ansi.Strip(note) != "mount details unavailable" {
		t.Fatalf("unavailable mount details presented as known access: %q / %q", ansi.Strip(value), ansi.Strip(note))
	}
	m.mounts = []tuiMountRow{{Sandbox: "codex-dev", Error: "unavailable"}}
	_, note = m.overviewAccess(tuiThemeFor(true), m.sandboxes[0])
	if ansi.Strip(note) != "1 mount error" {
		t.Fatalf("mount error was presented as writable access: %q", ansi.Strip(note))
	}
}

func TestOverviewSummarySeparatesConfiguredFromActiveCPU(t *testing.T) {
	m := modernDashboardTestModel()
	m.page, m.width = tuiOverviewPage, 140
	m.limits.MaxVCPUs = 12
	m.sandboxes[0].ActiveAvailable, m.sandboxes[0].ActiveVCPUs = true, 2
	m.sandboxes[1].State = tuiStopped
	summary := ansi.Strip(m.tabSummary(tuiThemeFor(true)))
	if summary != "● 1 running · 16 vCPU configured · 12 host" {
		t.Fatalf("summary mislabels configured CPU counts: %q", summary)
	}
	menu := ansi.Strip(m.renderMenuBar(tuiThemeFor(true), m.width))
	if !strings.Contains(menu, summary) {
		t.Fatal("host summary disappeared when it did not fit beside navigation")
	}
	m.sandboxes[1].ConfigError = true
	if summary = ansi.Strip(m.tabSummary(tuiThemeFor(true))); !strings.Contains(summary, "12+? vCPU configured") {
		t.Fatalf("unknown configuration produced an exact CPU count: %q", summary)
	}
}

func TestOverviewCardStatusesRemainExplicitWithoutColor(t *testing.T) {
	m := modernDashboardTestModel()
	theme := tuiThemeFor(true)
	for _, state := range []string{"running", "stopped", "starting"} {
		sandbox := m.sandboxes[0]
		switch state {
		case "running":
			sandbox.State = tuiRunning
		case "stopped":
			sandbox.State = tuiStopped
		case "starting":
			sandbox.State = tuiStarting
		}
		for _, width := range []int{40, 76, 94, 112} {
			text := ansi.Strip(m.renderOperationalSandboxPanel(theme, width, 13, sandbox, true))
			if !strings.Contains(text, strings.ToUpper(state)) || !strings.Contains(text, "›") {
				t.Fatalf("width=%d: status/selection relies only on color:\n%s", width, text)
			}
		}
	}
}
