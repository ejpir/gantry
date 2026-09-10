package dashboard

import (
	"runtime"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
)

func TestStackIconsUseOrdinaryFixedWidthCharacters(t *testing.T) {
	for name, icon := range map[string]string{"cube": tuiStackCube, "chip": tuiStackChip, "gantry": tuiLogo} {
		if lipgloss.Height(icon) != 3 || lipgloss.Width(icon) > 6 {
			t.Fatalf("%s icon is not a compact 6x3 drawing", name)
		}
		for _, r := range icon {
			if r > 127 && (r < 0x2500 || r > 0x25ff) {
				t.Fatalf("%s requires a nonstandard icon glyph %U", name, r)
			}
		}
		for _, dark := range []bool{true, false} {
			rendered := renderStackIconLabel(tuiThemeFor(dark), icon, "Layer", "Description", 42, true)
			if lipgloss.Height(rendered) != 3 || lipgloss.Width(rendered) > 42 {
				t.Fatalf("%s icon altered label geometry", name)
			}
		}
	}
}

func TestSandboxStackLayersUseSelectedData(t *testing.T) {
	for _, dark := range []bool{true, false} {
		m := modernDashboardTestModel()
		m.page, m.dark = tuiSandboxesPage, dark
		selected := &m.sandboxes[0]
		selected.State = tuiStopped
		selected.DevContainersImage = "/Users/example/project/artifacts/gantry-ide-image-arm64.erofs"
		original := selected.DevContainersImage
		body, _ := m.renderSandboxStack(tuiThemeFor(dark), 118, 44)
		plain := ansi.Strip(body)
		backend, _ := stackHostBackend(runtime.GOOS)
		for _, want := range []string{"○ STOPPED", "enter Start", "e Edit", "i Details", "microVM boundary", "Workload", "Development", "gantry-ide-image-arm64.erofs", "32 GiB IDE disk", "SSH configured", "Gantry supervisor + workers", backend, "Network", "Access", "Attached", "Configured", " /__/|", "─┤□ ├─"} {
			if !strings.Contains(plain, want) {
				t.Fatalf("dark=%t stack missing %q:\n%s", dark, want, plain)
			}
		}
		for _, unwanted := range []string{"Private Linux", "/Users/example", "SSH ready", "gVisor", "confined workers"} {
			if strings.Contains(plain, unwanted) {
				t.Fatalf("stack contains an unnecessary path or incorrect state: %q", unwanted)
			}
		}
		if selected.DevContainersImage != original {
			t.Fatal("presentation overwrote the full configuration path")
		}
		selected.DevContainers, selected.SSH, selected.Net = false, false, false
		selected.Runtime = "runsc"
		body, _ = m.renderSandboxStack(tuiThemeFor(dark), 118, 44)
		plain = ansi.Strip(body)
		if strings.Contains(plain, "Development") || strings.Contains(plain, "IDE disk") || strings.Contains(plain, "Dev Containers") {
			t.Fatal("diagram invented a development environment")
		}
		for _, want := range []string{"gVisor / runsc runtime", "network disabled", "SSH disabled"} {
			if !strings.Contains(plain, want) {
				t.Fatalf("selected configuration missing %q", want)
			}
		}
	}
}

func TestStackHostBackendLabels(t *testing.T) {
	for _, tc := range [][3]string{{"linux", "KVM", "Linux"}, {"darwin", "Hypervisor.framework", "macOS"}, {"windows", "WHPX", "Windows"}, {"other", "Platform hypervisor", "other"}} {
		backend, host := stackHostBackend(tc[0])
		if backend != tc[1] || host != tc[2] {
			t.Fatalf("%s backend = %s / %s", tc[0], backend, host)
		}
	}
}

func TestStackImageLabelsRetainOCIIdentityAndShortenOnlyPaths(t *testing.T) {
	for _, tc := range [][2]string{
		{"/home/me/ide.erofs", "ide.erofs"}, {`C:\Users\me\ide.erofs`, "ide.erofs"},
		{"file:///Users/me/ide.erofs", "ide.erofs"}, {"docker.io/library/ubuntu:latest", "ubuntu:latest"},
		{"registry.example:5000/team/dev:v1", "registry.example:5000/team/dev:v1"},
		{"ghcr.io/org/image@sha256:abc", "ghcr.io/org/image@sha256:abc"},
	} {
		if got := stackImageLabel(tc[0]); got != tc[1] {
			t.Fatalf("image %q became %q, want %q", tc[0], got, tc[1])
		}
	}
}

func TestStackAdaptsWithoutClippingFactsOrMouseTargets(t *testing.T) {
	for _, dark := range []bool{true, false} {
		for _, width := range []int{78, 90, 100, 120, 140, 170, 236, 300} {
			for _, height := range []int{29, 30, 36, 40, 55} {
				for _, development := range []bool{true, false} {
					m := modernDashboardTestModel()
					m.page, m.dark, m.width, m.height = tuiSandboxesPage, dark, width, height
					m.sandboxes[0].DevContainers = development
					layout := m.dashboardLayout()
					geometry := m.masterDetailGeometry(layout)
					if geometry.detailWidth > tuiStackMaxWidth || geometry.detailOffset+geometry.detailWidth > width {
						t.Fatal("detail exceeds its readable width or viewport")
					}
					view := m.View().Content
					if lipgloss.Width(view) != width || lipgloss.Height(view) != height {
						t.Fatalf("%dx%d overflow", width, height)
					}
					body, _ := m.renderSandboxStack(tuiThemeFor(dark), geometry.detailWidth, layout.contentHeight-geometry.detailTop)
					for _, want := range []string{"Workload", "Gantry supervisor + workers", "Network", "Access", "Attached"} {
						if !strings.Contains(ansi.Strip(body), want) {
							t.Fatalf("%dx%d development=%t clipped %q:\n%s", width, height, development, want, ansi.Strip(body))
						}
					}
					plain := strings.Split(ansi.Strip(view), "\n")
					for _, hit := range m.dashboardHits {
						r := hit.rect
						if r.w <= 0 || r.h <= 0 || r.x < 0 || r.y < 0 || r.x+r.w > width || r.y+r.h > height {
							t.Fatalf("offscreen target %+v", hit)
						}
						got, ok := m.dashboardHitAt(layout, r.x+r.w/2, r.y+r.h/2)
						if !ok || got != hit {
							t.Fatalf("%dx%d target mismatch: %+v -> %+v", width, height, hit, got)
						}
						if hit.kind == "workload" {
							var rows []string
							for _, row := range plain[r.y : r.y+r.h] {
								rows = append(rows, ansi.Cut(row, r.x, r.x+r.w))
							}
							content := strings.Join(rows, "\n")
							if !strings.Contains(content, "Workload") || strings.Contains(content, "Development") {
								t.Fatalf("workload hit area is not the rendered node:\n%s", content)
							}
						}
					}
				}
			}
		}
	}
}

func TestRightPaneInsetKeepsSidebarAndMouseTargetsAligned(t *testing.T) {
	for _, dark := range []bool{true, false} {
		for _, filtered := range []bool{true, false} {
			m := modernDashboardTestModel()
			m.page, m.dark, m.width, m.height = tuiSandboxesPage, dark, 236, 55
			if filtered {
				m.applySandboxFilter("codex")
			}
			layout := m.dashboardLayout()
			geometry := m.masterDetailGeometry(layout)
			if geometry.detailTop != 1 {
				t.Fatal("right pane was not lowered one row")
			}
			for _, create := range []bool{false, true} {
				if create {
					m.cursor = len(m.sandboxes)
				}
				view := strings.Split(ansi.Strip(m.View().Content), "\n")
				x := layout.contentX + geometry.detailOffset
				if strings.TrimSpace(ansi.Cut(view[layout.contentY], x, x+geometry.detailWidth)) != "" {
					t.Fatal("right pane has no blank row above it")
				}
				if hit, ok := m.dashboardHitAt(layout, x+1, layout.contentY); ok {
					t.Fatalf("right-pane top padding is clickable: %+v", hit)
				}
				if !strings.Contains(ansi.Cut(view[layout.contentY+1], 0, geometry.listWidth), "Sandboxes") {
					t.Fatal("lowering the right pane moved the sidebar")
				}
				if !create && !strings.Contains(ansi.Cut(view[layout.contentY+1], x, x+geometry.detailWidth), "codex-dev") {
					t.Fatal("detail and sidebar headings are not aligned")
				}
			}
		}
	}
}

func TestStackKeepsIconsAtIntermediateHeights(t *testing.T) {
	m := modernDashboardTestModel()
	for _, height := range []int{27, 30, 34, 50} {
		body, _ := m.renderSandboxStack(tuiThemeFor(true), 118, height)
		if !strings.Contains(body, "─┤□ ├─") || !strings.Contains(body, " /__/|") {
			t.Fatalf("height %d dropped icons despite sufficient space", height)
		}
	}
}

func TestStackActionsFollowSelectionAndBusyState(t *testing.T) {
	m := modernDashboardTestModel()
	m.page = tuiSandboxesPage
	m.cursor = 1
	m.sandboxes[1].State = tuiStopped
	m.applySandboxFilter("testnick")
	_ = m.View()
	var edit tuiHitTarget
	for _, hit := range m.dashboardHits {
		if hit.kind == "shortcut" && hit.action == "e" && hit.rect.y < m.headerHeight()+5 {
			edit = hit
			break
		}
	}
	if edit.rect.w == 0 {
		t.Fatal("selected sandbox header has no Edit target")
	}
	_, _ = m.updateMouseClick(tea.Mouse{X: edit.rect.x + 1, Y: edit.rect.y, Button: tea.MouseLeft})
	if m.dialog != tuiEditDialog || m.selected().Name != "testnick" || m.editCPUs.Value != 4 {
		t.Fatal("header action was applied to the wrong sandbox")
	}
	m.closeDialog()
	m.busyAction, m.busyName = "start", "testnick"
	_ = m.View()
	for _, hit := range m.dashboardHits {
		if hit.kind == "shortcut" || hit.kind == "workload" || hit.kind == "create" {
			t.Fatalf("busy stack published action %+v", hit)
		}
	}
}

func TestStackDoesNotInventResourcesWhenConfigurationIsUnavailable(t *testing.T) {
	m := modernDashboardTestModel()
	m.sandboxes[0].ConfigError = true
	body, _ := m.renderSandboxStack(tuiThemeFor(true), 118, 44)
	plain := ansi.Strip(body)
	for _, want := range []string{"Configuration unavailable", "Storage unavailable", "Access unavailable", "Worker configuration unavailable"} {
		if !strings.Contains(plain, want) {
			t.Fatalf("missing unavailable-data indication %q", want)
		}
	}
	for _, unwanted := range []string{"12 vCPU", "60 GiB", "23.3 GiB", "SSH ready", "4 mounts", "enter Open"} {
		if strings.Contains(plain, unwanted) {
			t.Fatalf("missing configuration presented as valid data: %q", unwanted)
		}
	}
}
