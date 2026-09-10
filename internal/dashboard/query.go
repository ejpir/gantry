package dashboard

import (
	"fmt"
	"slices"
	"strings"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

// Source snapshots are never sorted or filtered in place. Actions and details
// consume the same projected rows as the screen; clearing a filter restores
// hidden rows without waiting for a refresh. Image/registry data is host-wide.
func (m *sandboxTUIModel) rememberViewSource() {
	if m.viewSource != nil {
		return
	}
	m.viewSource = &tuiRefreshMsg{sandboxes: m.sandboxes, traffic: m.traffic, rules: m.rules, mounts: m.mounts, ports: m.ports, secrets: m.secrets, mcp: m.mcpServers, images: m.images, registries: m.registries}
	m.packetSource = slices.Clone(m.packets)
}

func (m sandboxTUIModel) allSandboxes() []tuiSandbox {
	if m.viewSource != nil {
		return m.viewSource.sandboxes
	}
	return m.sandboxes
}

func filteredRows[T any](source []T, query string, sandbox func(T) string) []T {
	rows := make([]T, 0, len(source))
	query = strings.ToLower(query)
	for _, row := range source {
		if query == "" || strings.Contains(strings.ToLower(sandbox(row)), query) {
			rows = append(rows, row)
		}
	}
	return rows
}

func (m *sandboxTUIModel) rebuildRows() {
	if m.viewSource == nil {
		return
	}
	s := m.viewSource
	q := m.sandboxFilter
	m.sandboxes = filteredRows(s.sandboxes, q, func(r tuiSandbox) string { return r.Name })
	m.traffic = filteredRows(s.traffic, q, func(r tuiTrafficRow) string { return r.Sandbox })
	m.rules = filteredRows(s.rules, q, func(r tuiRuleRow) string { return r.Sandbox })
	m.mounts = filteredRows(s.mounts, q, func(r tuiMountRow) string { return r.Sandbox })
	m.ports = filteredRows(s.ports, q, func(r tuiPortRow) string { return r.Sandbox })
	m.secrets = filteredRows(s.secrets, q, func(r tuiSecretRow) string { return r.Sandbox })
	m.mcpServers = filteredRows(s.mcp, q, func(r tuiMCPRow) string { return r.Sandbox })
	m.packets = filteredRows(m.packetSource, q, func(r tuiPacketRow) string { return r.Sandbox })
	m.images, m.registries = slices.Clone(s.images), slices.Clone(s.registries)
	sandboxScope := tuiSandboxesPage
	if m.page == tuiOverviewPage {
		sandboxScope = tuiOverviewPage
	}
	sortRows(m.sandboxes, m.sorts[sandboxScope], sandboxSortValue)
	sortRows(m.traffic, m.sorts[tuiTrafficPage], trafficSortValue)
	sortRows(m.rules, m.sorts[tuiRulesPage], ruleSortValue)
	sortRows(m.mounts, m.sorts[tuiMountsPage], mountSortValue)
	sortRows(m.ports, m.sorts[tuiPortsPage], portSortValue)
	sortRows(m.secrets, m.sorts[tuiSecretsPage], secretSortValue)
	sortRows(m.mcpServers, m.sorts[tuiMCPPage], mcpSortValue)
	sortRows(m.packets, m.sorts[tuiPacketsPage], packetSortValue)
	sortRows(m.images, m.sorts[tuiImagesPage], imageSortValue)
	sortRows(m.registries, m.sorts[tuiPageCount], registrySortValue)
}

func (m sandboxTUIModel) selectedPacketKey() string {
	if m.packetCursor < 0 || m.packetCursor >= len(m.packets) {
		return ""
	}
	return packetRowKey(m.packets[m.packetCursor])
}
func packetRowKey(r tuiPacketRow) string {
	return fmt.Sprintf("%s\x00%d\x00%s", r.Sandbox, r.Sequence, r.Timestamp.Format("2006-01-02T15:04:05.999999999Z07:00"))
}
func (m *sandboxTUIModel) restorePacketSelection(key string) {
	if key != "" {
		m.packetCursor = 0
		for i, row := range m.packets {
			if packetRowKey(row) == key {
				m.packetCursor = i
				break
			}
		}
	}
	m.packetCursor = clampTableCursor(m.packetCursor, len(m.packets))
}

func (m *sandboxTUIModel) rebuildView(resetScroll bool) {
	name := ""
	if selected := m.selected(); selected != nil {
		name = selected.Name
	}
	newCard := m.page == tuiSandboxesPage && m.onNewCard()
	t, r, mount, port, secret, mcp, image, registry := m.selectedTableKeys()
	packet := m.selectedPacketKey()
	m.rebuildRows()
	if resetScroll {
		m.cursor, m.scrollRow = 0, 0
		m.trafficCursor, m.trafficScroll, m.rulesCursor, m.rulesScroll = 0, 0, 0, 0
		m.mountCursor, m.mountScroll, m.portCursor, m.portScroll = 0, 0, 0, 0
		m.secretCursor, m.secretScroll, m.mcpCursor, m.mcpScroll = 0, 0, 0, 0
		m.packetCursor, m.packetScroll = 0, 0
	}
	if newCard {
		m.cursor = len(m.sandboxes)
	} else {
		m.cursor = 0
		for i, row := range m.sandboxes {
			if row.Name == name {
				m.cursor = i
				break
			}
		}
	}
	m.restoreTableSelections(t, r, mount, port, secret, mcp, image, registry)
	m.restorePacketSelection(packet)
	m.ensureCursorVisible()
	m.ensureTableCursorVisible()
	m.dashboardHits = nil
	m.lastClickKind = ""
}

func (m *sandboxTUIModel) applySandboxFilter(query string) {
	m.rememberViewSource()
	m.sandboxFilter = strings.TrimSpace(safeUILine(query))
	m.rebuildView(true)
}

func (m *sandboxTUIModel) openFilterDialog() tea.Cmd {
	m.sandboxFilterInput = textinput.New()
	m.sandboxFilterInput.Prompt = ""
	m.sandboxFilterInput.Placeholder = "All sandboxes"
	m.sandboxFilterInput.CharLimit = 64
	m.sandboxFilterInput.SetValue(m.sandboxFilter)
	m.dialog, m.dialogScroll = tuiSandboxFilterDialog, 0
	m.applyInputTheme()
	m.resizeInputs()
	m.ensureDialogFocusVisible()
	return m.sandboxFilterInput.Focus()
}

func (m *sandboxTUIModel) updateFilterDialogKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.closeDialog()
		return m, nil
	case "enter":
		m.applySandboxFilter(m.sandboxFilterInput.Value())
		m.closeDialog()
		return m, nil
	default:
		var cmd tea.Cmd
		m.sandboxFilterInput, cmd = m.sandboxFilterInput.Update(msg)
		return m, cmd
	}
}

func (m sandboxTUIModel) renderFilterDialog(theme tuiTheme, width int) string {
	muted := lipgloss.NewStyle().Foreground(theme.muted)
	return m.dialogHeader(theme, "Filter by sandbox", width) + "\n\n" +
		formLabel(theme, "Sandbox name", true) + "\n" +
		renderInputField(theme, m.sandboxFilterInput.View(), width, true) + "\n\n" +
		muted.Render(lipgloss.Wrap("Case-insensitive name match across sandbox views. Images and registries remain host-wide.", width, "")) + "\n\n" +
		renderDialogButton(theme, "Apply", true, false) + " " + renderDialogButton(theme, "Clear", false, false) + "\n\n" +
		muted.Render(lipgloss.Wrap("enter apply · empty clears · esc cancel", width, ""))
}

func (m *sandboxTUIModel) openSortDialog() {
	m.dialog, m.dialogScroll, m.sortCursor = tuiSortDialog, 0, 0
	for i, column := range m.sortColumns() {
		if column.id == m.sorts[m.sortScope()].column {
			m.sortCursor = i + 1
		}
	}
	m.ensureDialogFocusVisible()
}

type tuiSortOption struct {
	id  string
	row int
}

func (m sandboxTUIModel) sortDialogLayout(theme tuiTheme, width int) (string, []tuiSortOption) {
	lines := strings.Split(m.dialogHeader(theme, "Sort "+strings.ToLower(pageDisplayTitle(m.page)), width), "\n")
	lines = append(lines, "")
	columns := append([]tuiSortColumn{{label: "Default order"}}, m.sortColumns()...)
	var options []tuiSortOption
	state := m.sorts[m.sortScope()]
	for i, column := range columns {
		label := "  " + column.label
		style := lipgloss.NewStyle().Foreground(theme.secondary)
		if i == m.sortCursor {
			label = "› " + column.label
			style = style.Foreground(theme.accent).Bold(true)
		}
		if column.id != "" && column.id == state.column {
			if state.desc {
				label += " ▼"
			} else {
				label += " ▲"
			}
		}
		options = append(options, tuiSortOption{id: column.id, row: len(lines)})
		lines = append(lines, style.Render(truncateText(label, width)))
	}
	lines = append(lines, "", lipgloss.NewStyle().Foreground(theme.muted).Render(lipgloss.Wrap("↑/↓ select · enter apply/reverse · esc cancel", width, "")))
	return strings.Join(lines, "\n"), options
}

func (m *sandboxTUIModel) updateSortDialogKey(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "esc", "q":
		m.closeDialog()
	case "up", "k":
		m.sortCursor = maxInt(0, m.sortCursor-1)
	case "down", "j":
		m.sortCursor = minInt(len(m.sortColumns()), m.sortCursor+1)
	case "home", "g":
		m.sortCursor = 0
	case "end", "G":
		m.sortCursor = len(m.sortColumns())
	case "enter":
		column := ""
		if m.sortCursor > 0 {
			column = m.sortColumns()[m.sortCursor-1].id
		}
		m.chooseSort(column)
		m.closeDialog()
	}
	m.ensureDialogFocusVisible()
	return m, nil
}

// Keep a blank row on both sides of the filter toolbar. Very short terminals
// use the compact header hint instead of sacrificing their last data rows.
func (m sandboxTUIModel) queryToolbarHeight() int {
	if m.sandboxFilter != "" && m.height >= 10 {
		return 2
	}
	return 0
}

func (m sandboxTUIModel) headerHeight() int { return tuiMenuHeight + m.queryToolbarHeight() }

func (m sandboxTUIModel) viewQueryLabel() string {
	if m.sandboxFilter == "" {
		return ""
	}
	label := "Sandbox filter: " + m.sandboxFilter + " · / change"
	if m.page == tuiImagesPage {
		label += " (host-wide view)"
	}
	return label
}

func (m sandboxTUIModel) viewSortLabel() string {
	state := m.sorts[m.sortScope()]
	for _, c := range m.sortColumns() {
		if c.id == state.column {
			arrow := " ▲"
			if state.desc {
				arrow = " ▼"
			}
			return "Sort: " + c.label + arrow + " · S change"
		}
	}
	return ""
}
