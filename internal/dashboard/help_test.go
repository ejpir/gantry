package dashboard

import (
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
)

func TestHelpCellsFitWithoutWrappingJoinedColumns(t *testing.T) {
	for _, dark := range []bool{true, false} {
		for _, width := range []int{18, 30, 50, 66, 90, 94, 104} {
			m := queryTestModel()
			m.dark = dark
			for page := tuiSandboxesPage; page < tuiPageCount; page++ {
				m.page = page
				body := m.renderKeyboardHelp(tuiThemeFor(dark), width)
				for row, line := range strings.Split(body, "\n") {
					if lipgloss.Width(line) > width {
						t.Fatalf("dark=%t width=%d page=%d row=%d exceeds its column: %q", dark, width, page, row, ansi.Strip(line))
					}
				}
				// The dialog's final wrap must not alter already bounded help rows.
				wrapped := lipgloss.Wrap(body, width, "")
				if lipgloss.Height(wrapped) != lipgloss.Height(body) {
					t.Fatalf("width=%d page=%d: final wrapping interleaves help cells", width, page)
				}
			}
		}
	}
}

func TestHelpShowsContextualBindingsAndQueryControls(t *testing.T) {
	m := queryTestModel()
	m.page = tuiTrafficPage
	body := ansi.Strip(m.renderKeyboardHelp(tuiThemeFor(true), 104))
	for _, text := range []string{"NAVIGATION", "TRAFFIC ACTIONS", "FILTER & SORT", "APPLICATION", "Filter by sandbox name", "Sort / reverse column", "Add allow / block rule", "Remove matching rule"} {
		if !strings.Contains(body, text) {
			t.Fatalf("help is missing %q", text)
		}
	}
	if strings.Contains(body, "Remove share") || strings.Contains(body, "Prune unused images") {
		t.Fatal("help mixes unrelated view actions")
	}
	m.page = tuiMCPPage
	body = ansi.Strip(m.renderKeyboardHelp(tuiThemeFor(true), 104))
	if !strings.Contains(body, "Configure filesystem server") || strings.Contains(body, "Add allow / block rule") {
		t.Fatal("help did not follow current tab")
	}
}

func TestQueryDialogsRemainBoundedAndScrollable(t *testing.T) {
	for _, size := range [][2]int{{24, 12}, {40, 16}, {60, 20}, {100, 30}, {170, 42}} {
		m := queryTestModel()
		m.width, m.height = size[0], size[1]
		for _, kind := range []tuiDialog{tuiHelpDialog, tuiSandboxFilterDialog, tuiSortDialog} {
			switch kind {
			case tuiSandboxFilterDialog:
				_ = m.openFilterDialog()
			case tuiSortDialog:
				m.openSortDialog()
				_, _ = m.updateSortDialogKey("end")
			default:
				m.dialog = kind
				m.dialogScroll = 0
			}
			view := m.View().Content
			if lipgloss.Width(view) != m.width || lipgloss.Height(view) != m.height {
				t.Fatalf("%dx%d dialog %d overflow", m.width, m.height, kind)
			}
			_, _ = m.updateDialogKey(tea.KeyPressMsg{Code: tea.KeyEsc})
			if m.dialog != tuiNoDialog {
				t.Fatal("query/help dialog cannot be cancelled")
			}
		}
	}
}
