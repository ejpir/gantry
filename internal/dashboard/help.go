package dashboard

import (
	"strings"

	"charm.land/lipgloss/v2"
)

type tuiHelpSection struct {
	title string
	rows  [][2]string
}

// Wrap each cell before joining columns. Wrapping the joined help as one block
// interleaves unrelated bindings when the dialog is narrower than its content.
func renderHelpSection(theme tuiTheme, section tuiHelpSection, width int) string {
	keyWidth := minInt(17, maxInt(8, width/3))
	descriptionWidth := maxInt(1, width-keyWidth-2)
	if width < 16 {
		keyWidth = maxInt(1, width/2-1)
		descriptionWidth = maxInt(1, width-keyWidth-2)
	}
	lines := []string{lipgloss.NewStyle().Bold(true).Foreground(theme.accent).Render(lipgloss.Wrap(section.title, width, ""))}
	for _, binding := range section.rows {
		keys := strings.Split(lipgloss.Wrap(binding[0], keyWidth, ""), "\n")
		descriptions := strings.Split(lipgloss.Wrap(binding[1], descriptionWidth, ""), "\n")
		for i := 0; i < maxInt(len(keys), len(descriptions)); i++ {
			key, description := "", ""
			if i < len(keys) {
				key = keys[i]
			}
			if i < len(descriptions) {
				description = descriptions[i]
			}
			lines = append(lines, lipgloss.NewStyle().Bold(true).Foreground(theme.text).Width(keyWidth).Render(key)+"  "+lipgloss.NewStyle().Foreground(theme.secondary).Render(description))
		}
	}
	return strings.Join(lines, "\n")
}

func (m sandboxTUIModel) helpViewActions() tuiHelpSection {
	section := tuiHelpSection{title: strings.ToUpper(pageDisplayTitle(m.page)) + " ACTIONS"}
	switch m.page {
	case tuiOverviewPage, tuiSandboxesPage:
		section.title = "SANDBOX ACTIONS"
		enter := "Open or start sandbox"
		if m.page == tuiOverviewPage {
			enter = "Open sandbox view"
		}
		section.rows = [][2]string{{"enter", enter}, {"s", "Start / stop"}, {"e", "Edit configuration"}, {"i", "Full details"}, {"d", "Remove sandbox"}}
		if m.page == tuiOverviewPage {
			section.rows = append(section.rows, [2]string{"t", "View selected sandbox traffic"})
		}
	case tuiTrafficPage:
		section.rows = [][2]string{{"a", "Add allow / block rule"}, {"r", "Remove matching rule"}, {"R", "Refresh traffic"}}
	case tuiRulesPage:
		section.rows = [][2]string{{"e", "Edit network policy"}, {"d", "Remove policy entry"}, {"r", "Refresh rules"}}
	case tuiMountsPage:
		section.rows = [][2]string{{"a", "Add share"}, {"r", "Replace share"}, {"d", "Remove share"}, {"R", "Refresh mounts"}}
	case tuiPortsPage:
		section.rows = [][2]string{{"p", "Publish port"}, {"d", "Unpublish port"}, {"r", "Refresh ports"}}
	case tuiSecretsPage:
		section.rows = [][2]string{{"a", "Add secret"}, {"d", "Delete secret"}, {"r", "Refresh names"}}
	case tuiMCPPage:
		section.rows = [][2]string{{"a", "Add remote server"}, {"f", "Configure filesystem server"}, {"e", "Edit selected server"}, {"d", "Remove remote server"}}
	case tuiPacketsPage:
		section.rows = [][2]string{{"enter / d", "Inspect packet"}, {"space", "Pause / resume display"}, {"c", "Clear packet capture"}, {"r", "Refresh capture"}}
	case tuiImagesPage:
		section.rows = [][2]string{{"p", "Pull image"}, {"d", "Remove image"}, {"u", "Prune unused images"}, {"s", "Switch to registries"}}
		if m.imageSection == tuiImageSectionCredentials {
			section.rows = [][2]string{{"a", "Store registry login"}, {"d", "Remove stored login"}, {"s", "Switch to images"}}
		}
	}
	return section
}

func (m sandboxTUIModel) renderKeyboardHelp(theme tuiTheme, width int) string {
	navigation := tuiHelpSection{"NAVIGATION", [][2]string{
		{"↑/↓ or j/k", "Move selection"}, {"tab / shift+tab", "Switch views"},
		{"0…9", "Jump to a view"}, {"g / G", "First / last row"},
		{"Mouse wheel", "Scroll"}, {"Click", "Select row or action"},
	}}
	if m.page != tuiOverviewPage {
		navigation.rows = append(navigation.rows, [2]string{"pgup / pgdown", "Move one page"})
	}
	query := tuiHelpSection{"FILTER & SORT", [][2]string{
		{"/", "Filter by sandbox name"}, {"Empty + enter", "Clear sandbox filter"},
		{"S", "Choose sort field / order"}, {"Click header", "Sort / reverse column"},
	}}
	application := tuiHelpSection{"APPLICATION", [][2]string{
		{"n", "Create sandbox"}, {"?", "Open / close help"},
		{"esc", "Close dialog"}, {"q / ctrl+c", "Quit outside dialogs"},
		{"ctrl+c / ctrl+v", "Copy / paste in forms"},
	}}
	if m.updateStatus.Available {
		application.rows = append(application.rows, [2]string{"U", "Install " + m.updateStatus.Latest})
	}
	var body string
	if width >= 94 {
		columnWidth := (width - 4) / 2
		left := renderHelpSection(theme, navigation, columnWidth) + "\n\n" + renderHelpSection(theme, query, columnWidth)
		right := renderHelpSection(theme, m.helpViewActions(), columnWidth) + "\n\n" + renderHelpSection(theme, application, columnWidth)
		body = lipgloss.JoinHorizontal(lipgloss.Top, lipgloss.NewStyle().Width(columnWidth).Render(left), "    ", lipgloss.NewStyle().Width(columnWidth).Render(right))
	} else {
		var sections []string
		for _, section := range []tuiHelpSection{navigation, m.helpViewActions(), query, application} {
			sections = append(sections, renderHelpSection(theme, section, width))
		}
		body = strings.Join(sections, "\n\n")
	}
	footer := lipgloss.NewStyle().Foreground(theme.muted).Render(lipgloss.Wrap("↑/↓ scroll help · esc close", width, ""))
	return m.dialogHeader(theme, "Keyboard shortcuts", width) + "\n\n" + body + "\n\n" + footer
}
