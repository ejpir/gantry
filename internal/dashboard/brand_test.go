package dashboard

import (
	"strings"
	"testing"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
)

func TestHeaderBrandFitsExistingHeader(t *testing.T) {
	for _, dark := range []bool{true, false} {
		for _, width := range []int{24, 40, 70, 79, 80, 81, 100, 120, 170} {
			brand := renderHeaderBrand(tuiThemeFor(dark), width)
			if got := lipgloss.Width(brand); got != headerBrandWidth(width) {
				t.Fatalf("dark=%t width=%d: brand width %d, geometry %d", dark, width, got, headerBrandWidth(width))
			}
			if got := lipgloss.Height(brand); got != tuiMenuHeight-tuiHeaderGap {
				t.Fatalf("dark=%t width=%d: brand height %d leaves no header gap", dark, width, got)
			}
			lines := strings.Split(ansi.Strip(brand), "\n")
			if !strings.Contains(lines[tuiTopPadding], "gantry.") {
				t.Fatalf("width=%d: wordmark is not on the navigation row: %q", width, lines)
			}
			if hasLogo := strings.Contains(lines[0], "┌───┐"); hasLogo != (width >= tuiLogoMinWidth) {
				t.Fatalf("width=%d: unexpected responsive logo: %q", width, lines)
			}
		}
	}
}

func TestBrandedNavigationMatchesMouseTargets(t *testing.T) {
	for _, dark := range []bool{true, false} {
		for _, width := range []int{24, 40, 70, 79, 80, 81, 100, 110, 119, 120, 130, 170} {
			for _, update := range []bool{false, true} {
				m := modernDashboardTestModel()
				m.dark, m.width = dark, width
				m.updateStatus.Available, m.updateStatus.Latest = update, "v0.0.99"
				for page := tuiSandboxesPage; page < tuiPageCount; page++ {
					m.page = page
					theme := tuiThemeFor(dark)
					menu := m.renderMenuBar(theme, width)
					if lipgloss.Width(menu) != width || lipgloss.Height(menu) != tuiMenuHeight {
						t.Fatalf("dark=%t width=%d update=%t: menu is %dx%d", dark, width, update, lipgloss.Width(menu), lipgloss.Height(menu))
					}
					menuLines := strings.Split(ansi.Strip(menu), "\n")
					for row := tuiMenuHeight - tuiHeaderGap; row < tuiMenuHeight; row++ {
						if strings.TrimSpace(menuLines[row]) != "" {
							t.Fatalf("width=%d: header gap contains content: %q", width, menuLines[row])
						}
					}
					line := menuLines[tuiTopPadding]
					tabs := m.tabRects(width)
					for _, tab := range tabs {
						if got := ansi.Cut(line, tab.x, tab.x+tab.w); got != tab.label {
							t.Fatalf("width=%d page=%d: tab %q renders as %q at its mouse target", width, page, tab.label, got)
						}
					}
					_ = m.View()
					for _, target := range m.dashboardHits {
						if target.kind != "page" && target.kind != "cycle-page" && target.kind != "menu" {
							continue
						}
						if target.rect.x < 2+headerBrandWidth(width) || target.rect.y != tuiTopPadding || target.rect.w < 1 || target.rect.x+target.rect.w > width {
							t.Fatalf("width=%d page=%d: header target overlaps logo or leaves viewport: %+v", width, page, target)
						}
						x := target.rect.x + target.rect.w/2
						got, ok := m.dashboardHitAt(m.dashboardLayout(), x, target.rect.y)
						if !ok || got != target {
							t.Fatalf("width=%d: header target does not resolve to itself: %+v -> %+v", width, target, got)
						}
					}
				}
			}
		}
	}
}

func TestBrandedDashboardResponsiveRendering(t *testing.T) {
	for _, dark := range []bool{true, false} {
		for _, size := range [][2]int{{40, 12}, {70, 22}, {79, 28}, {80, 24}, {80, 30}, {100, 30}, {120, 40}, {170, 40}} {
			m := modernDashboardTestModel()
			m.dark, m.width, m.height = dark, size[0], size[1]
			for page := tuiSandboxesPage; page < tuiPageCount; page++ {
				m.page = page
				view := m.View().Content
				if lipgloss.Width(view) != m.width || lipgloss.Height(view) != m.height {
					t.Fatalf("dark=%t %dx%d page=%d: rendered %dx%d", dark, m.width, m.height, page, lipgloss.Width(view), lipgloss.Height(view))
				}
			}
		}
	}
}

func TestSandboxStackReplacesKernelBand(t *testing.T) {
	for _, dark := range []bool{true, false} {
		m := modernDashboardTestModel()
		m.page, m.dark = tuiSandboxesPage, dark
		view := ansi.Strip(m.View().Content)
		if strings.Contains(view, "Private Linux kernel") {
			t.Fatalf("removed kernel band still appears:\n%s", view)
		}
		for _, want := range []string{"microVM boundary", "Workload", "Development", "Gantry supervisor + workers", "Network", "Access", "Attached", "Configured"} {
			if !strings.Contains(view, want) {
				t.Fatalf("stack layout displaced %q from topology", want)
			}
		}
	}
}

func TestEmptyOverviewLogoRespectsAvailableHeight(t *testing.T) {
	for _, height := range []int{8, 12, 16, 24} {
		m := modernDashboardTestModel()
		m.page, m.width, m.height = tuiOverviewPage, 60, height
		m.sandboxes = nil
		layout := m.dashboardLayout()
		body := m.renderOperationalDashboard(tuiThemeFor(m.dark), layout)
		plain := ansi.Strip(body)
		if strings.Contains(plain, "┌───┐") != (layout.contentHeight >= 9) {
			t.Fatalf("height=%d: logo did not adapt to available space", height)
		}
		if !strings.Contains(plain, "No sandboxes") || !strings.Contains(plain, "Press n to create one.") {
			t.Fatalf("height=%d: empty-state instructions were displaced", height)
		}
		if lipgloss.Height(body) != layout.contentHeight || lipgloss.Width(body) != layout.width {
			t.Fatalf("height=%d: empty-state logo changed layout dimensions", height)
		}
	}
}
