package dashboard

import (
	"fmt"
	"image/color"
	"strings"
	"time"

	dashboardapi "github.com/ejpir/gantry/internal/dashboard/api"

	"charm.land/lipgloss/v2"
)

type tuiSidebarItem struct {
	page  tuiPage
	key   string
	label string
	count int
}

type tuiOverviewGeometry struct {
	innerWidth                int
	metricCols, metricRows    int
	metricWidth, metricHeight int
	healthCols, healthWidth   int
	healthY, healthGap        int
	visible, start, end       int
	entryRects                map[int]tuiRect
}

type tuiMasterDetailGeometry struct {
	listWidth, detailWidth int
	visible, start, end    int
	entryRects             map[int]tuiRect
}

func pageDisplayTitle(page tuiPage) string {
	switch page {
	case tuiOverviewPage:
		return "Overview"
	case tuiTrafficPage:
		return "Traffic"
	case tuiRulesPage:
		return "Network rules"
	case tuiMountsPage:
		return "Mounts"
	case tuiPortsPage:
		return "Ports"
	case tuiSecretsPage:
		return "Secrets"
	case tuiMCPPage:
		return "MCP"
	case tuiPacketsPage:
		return "Packets"
	case tuiImagesPage:
		return "Images"
	default:
		return "Sandboxes"
	}
}

func pageShortcut(page tuiPage) string {
	switch page {
	case tuiOverviewPage:
		return "0"
	case tuiSandboxesPage:
		return "1"
	case tuiTrafficPage:
		return "2"
	case tuiRulesPage:
		return "3"
	case tuiMountsPage:
		return "4"
	case tuiPortsPage:
		return "5"
	case tuiSecretsPage:
		return "6"
	case tuiMCPPage:
		return "7"
	case tuiPacketsPage:
		return "8"
	case tuiImagesPage:
		return "9"
	default:
		return ""
	}
}

func (m sandboxTUIModel) sidebarItems() []tuiSidebarItem {
	return []tuiSidebarItem{
		{page: tuiOverviewPage, key: "0", label: "Overview", count: -1},
		{page: tuiSandboxesPage, key: "1", label: "Sandboxes", count: len(m.sandboxes)},
		{page: tuiTrafficPage, key: "2", label: "Traffic", count: len(m.traffic)},
		{page: tuiRulesPage, key: "3", label: "Network rules", count: len(m.rules)},
		{page: tuiMountsPage, key: "4", label: "Mounts", count: len(m.mounts)},
		{page: tuiPortsPage, key: "5", label: "Ports", count: len(m.ports)},
		{page: tuiSecretsPage, key: "6", label: "Secrets", count: len(m.secrets)},
		{page: tuiMCPPage, key: "7", label: "MCP", count: len(m.mcpServers)},
		{page: tuiPacketsPage, key: "8", label: "Packets", count: len(m.packets)},
		{page: tuiImagesPage, key: "9", label: "Images", count: len(m.images)},
	}
}

func (m sandboxTUIModel) renderSidebar(theme tuiTheme, layout tuiDashboardLayout) string {
	innerWidth := maxInt(8, layout.sidebarWidth-4)
	lines := []string{
		lipgloss.NewStyle().Bold(true).Foreground(theme.muted).Width(innerWidth).Align(lipgloss.Center).Render("Workspace"),
		lipgloss.NewStyle().Foreground(theme.borderMuted).Render(strings.Repeat("─", innerWidth)),
	}
	for _, item := range m.sidebarItems() {
		key := lipgloss.NewStyle().Foreground(theme.muted).Render("[" + item.key + "]")
		label := lipgloss.NewStyle().Foreground(theme.secondary).Render(item.label)
		right := ""
		if item.count >= 0 {
			right = lipgloss.NewStyle().Foreground(theme.muted).Render(fmt.Sprint(item.count))
		}
		lineWidth := maxInt(1, innerWidth-1)
		line := joinSides(key+" "+label, right, lineWidth)
		if item.page == m.page {
			line = lipgloss.NewStyle().Bold(true).Foreground(theme.text).Background(theme.panelSelected).Render(
				lipgloss.NewStyle().Foreground(theme.accent).Render("▌") + line,
			)
		} else {
			line = " " + line
		}
		lines = append(lines, line)
	}

	actions := []string{
		lipgloss.NewStyle().Bold(true).Foreground(theme.accent).Render("n") + lipgloss.NewStyle().Foreground(theme.secondary).Render("  New sandbox"),
		lipgloss.NewStyle().Bold(true).Foreground(theme.accent).Render("?") + lipgloss.NewStyle().Foreground(theme.secondary).Render("  Help"),
	}
	contentRows := maxInt(1, layout.contentHeight-2)
	if m.sidebarActionsVisible(layout) {
		for len(lines)+len(actions) < contentRows {
			lines = append(lines, "")
		}
		lines = append(lines, actions...)
	} else if len(lines) < contentRows {
		lines = append(lines, make([]string, contentRows-len(lines))...)
	}
	if len(lines) > contentRows {
		lines = lines[:contentRows]
	}
	content := strings.Join(lines, "\n")
	style := lipgloss.NewStyle().
		Foreground(theme.secondary).
		Background(theme.panel).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(theme.borderMuted).
		Padding(0, 1).
		Width(layout.sidebarWidth).
		Height(layout.contentHeight).
		MaxHeight(layout.contentHeight)
	return renderSurface(style, theme.secondary, theme.panel, content)
}

func (m sandboxTUIModel) sidebarActionsVisible(layout tuiDashboardLayout) bool {
	const headingRows = 2
	const actionRows = 2
	contentRows := maxInt(1, layout.contentHeight-2)
	return contentRows >= headingRows+len(m.sidebarItems())+actionRows
}

func (m sandboxTUIModel) usesMasterDetail(layout tuiDashboardLayout) bool {
	return m.page == tuiSandboxesPage && layout.width >= 78 && layout.contentHeight >= 16 && !m.loading
}

func (m sandboxTUIModel) overviewGeometry(layout tuiDashboardLayout) tuiOverviewGeometry {
	geometry := tuiOverviewGeometry{innerWidth: maxInt(20, layout.width-4), healthGap: 2, entryRects: make(map[int]tuiRect)}
	geometry.metricCols = 1
	if geometry.innerWidth >= 96 {
		geometry.metricCols = 4
	} else if geometry.innerWidth >= 52 {
		geometry.metricCols = 2
	}
	geometry.metricRows = (4 + geometry.metricCols - 1) / geometry.metricCols
	geometry.metricWidth = (geometry.innerWidth - 2*(geometry.metricCols-1)) / geometry.metricCols
	geometry.metricHeight = geometry.metricRows * 5
	geometry.healthCols = 1
	if geometry.innerWidth >= 92 {
		geometry.healthCols = 2
	}
	geometry.healthWidth = geometry.innerWidth
	if geometry.healthCols > 1 {
		geometry.healthWidth = (geometry.innerWidth - geometry.healthGap) / 2
	}
	geometry.healthY = layout.contentY + 4 + geometry.metricHeight
	geometry.visible = m.overviewVisibleItems(layout, geometry.metricHeight, geometry.healthCols)
	if geometry.visible > 0 {
		geometry.start = clampInt(m.scrollRow, 0, maxInt(0, m.entryCount()-geometry.visible))
		geometry.end = minInt(m.entryCount(), geometry.start+geometry.visible)
	}
	for index := geometry.start; index < geometry.end; index++ {
		position := index - geometry.start
		row, column := position/geometry.healthCols, position%geometry.healthCols
		geometry.entryRects[index] = tuiRect{
			x: layout.contentX + 2 + column*(geometry.healthWidth+geometry.healthGap),
			y: geometry.healthY + row*6,
			w: geometry.healthWidth,
			h: 6,
		}
	}
	return geometry
}

func (m sandboxTUIModel) masterDetailGeometry(layout tuiDashboardLayout) tuiMasterDetailGeometry {
	geometry := tuiMasterDetailGeometry{entryRects: make(map[int]tuiRect)}
	geometry.listWidth = clampInt(layout.width/4, 30, 40)
	geometry.detailWidth = maxInt(38, layout.width-geometry.listWidth-1)
	geometry.visible = maxInt(1, (layout.contentHeight-4)/4)
	geometry.start = clampInt(m.scrollRow, 0, maxInt(0, m.entryCount()-geometry.visible))
	geometry.end = minInt(m.entryCount(), geometry.start+geometry.visible)
	for index := geometry.start; index < geometry.end; index++ {
		geometry.entryRects[index] = tuiRect{
			x: layout.contentX + 2,
			y: layout.contentY + 3 + (index-geometry.start)*4,
			w: maxInt(1, geometry.listWidth-4),
			h: 4,
		}
	}
	return geometry
}

func (m sandboxTUIModel) renderOperationalDashboard(theme tuiTheme, layout tuiDashboardLayout) string {
	if m.loading {
		loading := m.spinner.View() + " " + lipgloss.NewStyle().Foreground(theme.secondary).Render("Discovering local sandboxes…")
		style := lipgloss.NewStyle().Foreground(theme.text).Background(theme.bg).Width(layout.width).Height(layout.contentHeight).Align(lipgloss.Center, lipgloss.Center)
		return renderSurface(style, theme.text, theme.bg, loading)
	}

	geometry := m.overviewGeometry(layout)
	innerWidth := geometry.innerWidth
	updated := relativeUpdate(m.lastUpdate)
	if updated == "" {
		updated = "local state"
	}
	title := joinSides(
		lipgloss.NewStyle().Bold(true).Foreground(theme.text).Render("Overview"),
		lipgloss.NewStyle().Foreground(theme.muted).Render(updated),
		innerWidth,
	)

	running, stopped, starting := 0, 0, 0
	var tx, rx uint64
	var allocated uint
	for _, sandbox := range m.sandboxes {
		switch sandbox.State {
		case tuiRunning:
			running++
		case tuiStarting:
			starting++
		default:
			stopped++
		}
		tx += sandbox.TXBytes
		rx += sandbox.RXBytes
		allocated += sandbox.DiskSizeMiB
		if sandbox.DevContainers {
			allocated += sandbox.DevContainersDiskMiB
		}
	}
	loadedSecrets := 0
	for _, secret := range m.secrets {
		if secret.State == "loaded" {
			loadedSecrets++
		}
	}
	metrics := []struct{ title, value, detail string }{
		{"Sandboxes", fmt.Sprintf("%d running", running), fmt.Sprintf("%d starting · %d stopped", starting, stopped)},
		{"Network", "↓ " + formatNetworkBytes(rx), "↑ " + formatNetworkBytes(tx)},
		{"Storage", formatMiBHuman(allocated), "allocated writable disks"},
		{"Security", fmt.Sprintf("%d rules", len(m.rules)), fmt.Sprintf("%d loaded secrets", loadedSecrets)},
	}
	metricGap := 2
	var metricRows []string
	for index := 0; index < len(metrics); index += geometry.metricCols {
		var cards []string
		for column := 0; column < geometry.metricCols && index+column < len(metrics); column++ {
			metric := metrics[index+column]
			cards = append(cards, renderOverviewMetric(theme, geometry.metricWidth, metric.title, metric.value, metric.detail))
		}
		metricRows = append(metricRows, lipgloss.JoinHorizontal(lipgloss.Top, intersperse(cards, strings.Repeat(" ", metricGap))...))
	}
	metricBlock := strings.Join(metricRows, "\n")

	healthTitle := lipgloss.NewStyle().Bold(true).Foreground(theme.muted).Render("SANDBOX HEALTH")
	var healthRows []string
	for index := geometry.start; index < geometry.end; index += geometry.healthCols {
		var cards []string
		for column := 0; column < geometry.healthCols && index+column < geometry.end; column++ {
			entry := index + column
			if entry == len(m.sandboxes) {
				cards = append(cards, renderOverviewNewCard(theme, geometry.healthWidth, entry == m.cursor))
			} else {
				cards = append(cards, m.renderOverviewSandbox(theme, geometry.healthWidth, m.sandboxes[entry], entry == m.cursor))
			}
		}
		healthRows = append(healthRows, lipgloss.JoinHorizontal(lipgloss.Top, intersperse(cards, strings.Repeat(" ", geometry.healthGap))...))
	}
	content := title + "\n\n" + metricBlock + "\n\n" + healthTitle
	if len(healthRows) > 0 {
		content += "\n" + strings.Join(healthRows, "\n")
	}
	content = sliceBlockLines(content, 0, layout.contentHeight)
	style := lipgloss.NewStyle().Foreground(theme.text).Background(theme.bg).Padding(0, 2).Width(layout.width).Height(layout.contentHeight).MaxHeight(layout.contentHeight)
	return renderSurface(style, theme.text, theme.bg, content)
}

func (m sandboxTUIModel) overviewVisibleItems(layout tuiDashboardLayout, metricHeight, healthCols int) int {
	rows := maxInt(0, (layout.contentHeight-metricHeight-5)/6)
	return rows * maxInt(1, healthCols)
}

func (m sandboxTUIModel) overviewNavigationCapacity(layout tuiDashboardLayout) int {
	return maxInt(1, m.overviewGeometry(layout).visible)
}

func renderOverviewMetric(theme tuiTheme, width int, title, value, detail string) string {
	inner := maxInt(4, width-4)
	content := lipgloss.NewStyle().Bold(true).Foreground(theme.muted).Render(truncateText(title, inner)) + "\n" +
		lipgloss.NewStyle().Bold(true).Foreground(theme.text).Render(truncateText(value, inner)) + "\n" +
		lipgloss.NewStyle().Foreground(theme.secondary).Render(truncateText(detail, inner))
	style := lipgloss.NewStyle().Foreground(theme.text).Background(theme.panel).Border(lipgloss.RoundedBorder()).BorderForeground(theme.borderMuted).Padding(0, 1).Width(width).Height(5).MaxHeight(5)
	return renderSurface(style, theme.text, theme.panel, content)
}

func (m sandboxTUIModel) renderOverviewSandbox(theme tuiTheme, width int, sandbox tuiSandbox, selected bool) string {
	border, background := theme.borderMuted, theme.panel
	if selected {
		border, background = theme.accent, theme.panelSelected
	}
	inner := maxInt(8, width-4)
	header := joinSides(lipgloss.NewStyle().Bold(true).Foreground(theme.text).Render(truncateText(sandbox.Name, maxInt(4, inner-14))), m.renderSandboxState(theme, sandbox), inner)
	image := lipgloss.NewStyle().Foreground(theme.secondary).Render(truncateText(shortImageRef(sandbox.Image), inner))
	resources := fmt.Sprintf("%d vCPU  ·  %s RAM  ·  %s disk", maxInt(1, sandbox.VCPUs), formatMiBHuman(sandbox.MemMB), formatMiBHuman(sandbox.DiskSizeMiB))
	features := sandboxFeatureSummary(sandbox)
	content := strings.Join([]string{header, image, lipgloss.NewStyle().Foreground(theme.secondary).Render(truncateText(resources, inner)), lipgloss.NewStyle().Foreground(theme.muted).Render(truncateText(features, inner))}, "\n")
	style := lipgloss.NewStyle().Foreground(theme.text).Background(background).Border(lipgloss.RoundedBorder()).BorderForeground(border).Padding(0, 1).Width(width).Height(6).MaxHeight(6)
	return renderSurface(style, theme.text, background, content)
}

func renderOverviewNewCard(theme tuiTheme, width int, selected bool) string {
	border, background := theme.borderMuted, theme.panel
	if selected {
		border, background = theme.accent, theme.panelSelected
	}
	content := lipgloss.JoinVertical(lipgloss.Center,
		lipgloss.NewStyle().Bold(true).Foreground(theme.accent).Render("＋"),
		lipgloss.NewStyle().Bold(true).Foreground(theme.text).Render("New sandbox"),
		lipgloss.NewStyle().Foreground(theme.muted).Render("n / enter to create"),
	)
	style := lipgloss.NewStyle().Foreground(theme.text).Background(background).Border(lipgloss.RoundedBorder()).BorderForeground(border).Width(width).Height(6).MaxHeight(6).Align(lipgloss.Center, lipgloss.Center)
	return renderSurface(style, theme.text, background, content)
}

func (m sandboxTUIModel) renderSandboxMasterDetail(theme tuiTheme, layout tuiDashboardLayout) string {
	geometry := m.masterDetailGeometry(layout)
	list := m.renderSandboxMasterList(theme, geometry, layout.contentHeight)
	detail := m.renderSandboxTopology(theme, geometry.detailWidth, layout.contentHeight)
	return lipgloss.JoinHorizontal(lipgloss.Top, list, " ", detail)
}

func (m sandboxTUIModel) masterVisibleItems(layout tuiDashboardLayout) int {
	return m.masterDetailGeometry(layout).visible
}

func (m sandboxTUIModel) renderSandboxMasterList(theme tuiTheme, geometry tuiMasterDetailGeometry, height int) string {
	width := geometry.listWidth
	inner := maxInt(8, width-4)
	lines := []string{
		joinSides(lipgloss.NewStyle().Bold(true).Foreground(theme.text).Render("Sandboxes"), lipgloss.NewStyle().Foreground(theme.muted).Render(fmt.Sprint(len(m.sandboxes))), inner),
		lipgloss.NewStyle().Foreground(theme.borderMuted).Render(strings.Repeat("─", inner)),
	}
	for index := geometry.start; index < geometry.end; index++ {
		if index == len(m.sandboxes) {
			line := lipgloss.NewStyle().Foreground(theme.accent).Render("＋") + " " + lipgloss.NewStyle().Bold(true).Foreground(theme.text).Render("New sandbox")
			if index == m.cursor {
				line = lipgloss.NewStyle().Background(theme.panelSelected).Render("▌" + truncateANSI(line, inner-1))
			} else {
				line = " " + line
			}
			lines = append(lines, line, lipgloss.NewStyle().Foreground(theme.muted).Render("  n / enter to create"), "", "")
			continue
		}
		sandbox := m.sandboxes[index]
		state := lipgloss.NewStyle().Foreground(sandboxStateColor(theme, sandbox.State)).Render("●")
		name := lipgloss.NewStyle().Bold(true).Foreground(theme.text).Render(truncateText(sandbox.Name, maxInt(4, inner-4)))
		first := state + " " + name
		if index == m.cursor {
			first = lipgloss.NewStyle().Background(theme.panelSelected).Render(lipgloss.NewStyle().Foreground(theme.accent).Render("▌") + truncateANSI(first, inner-1))
		} else {
			first = " " + first
		}
		image := "  " + lipgloss.NewStyle().Foreground(theme.secondary).Render(truncateText(shortImageRef(sandbox.Image), maxInt(4, inner-2)))
		resources := fmt.Sprintf("  %d vCPU · %s", maxInt(1, sandbox.VCPUs), formatMiBHuman(sandbox.MemMB))
		features := "  " + sandboxFeatureSummary(sandbox)
		lines = append(lines, first, image, lipgloss.NewStyle().Foreground(theme.muted).Render(truncateText(resources, inner)), lipgloss.NewStyle().Foreground(theme.muted).Render(truncateText(features, inner)))
	}
	content := strings.Join(lines, "\n")
	style := lipgloss.NewStyle().Foreground(theme.secondary).Background(theme.panel).Border(lipgloss.RoundedBorder()).BorderForeground(theme.borderMuted).Padding(0, 1).Width(width).Height(height).MaxHeight(height)
	return renderSurface(style, theme.secondary, theme.panel, content)
}

func (m sandboxTUIModel) renderSandboxTopology(theme tuiTheme, width, height int) string {
	inner := maxInt(12, width-4)
	selected := m.selected()
	if selected == nil {
		content := lipgloss.JoinVertical(lipgloss.Center,
			lipgloss.NewStyle().Bold(true).Foreground(theme.accent).Render("＋"),
			lipgloss.NewStyle().Bold(true).Foreground(theme.text).Render("Create a sandbox"),
			lipgloss.NewStyle().Foreground(theme.secondary).Render("Choose an image and allocate a local microVM."),
			lipgloss.NewStyle().Foreground(theme.muted).Render("Press enter or n to continue."),
		)
		style := lipgloss.NewStyle().Foreground(theme.text).Background(theme.panel).Border(lipgloss.RoundedBorder()).BorderForeground(theme.accent).Width(width).Height(height).MaxHeight(height).Align(lipgloss.Center, lipgloss.Center)
		return renderSurface(style, theme.text, theme.panel, content)
	}

	header := joinSides(
		lipgloss.NewStyle().Bold(true).Foreground(theme.text).Render(truncateText(selected.Name, maxInt(4, inner-18))),
		m.renderSandboxState(theme, *selected), inner,
	)
	vmSummary := fmt.Sprintf("microVM  ·  %d vCPU  ·  %s RAM  ·  %s", maxInt(1, selected.VCPUs), formatMiBHuman(selected.MemMB), defaultText(selected.Runtime, "runtime unknown"))
	separator := lipgloss.NewStyle().Foreground(theme.borderMuted).Render(strings.Repeat("─", inner))

	workloadWidth := inner
	developmentWidth := 0
	if selected.DevContainers && inner >= 62 {
		workloadWidth = (inner - 2) / 2
		developmentWidth = inner - workloadWidth - 2
	}
	workload := renderTopologyNode(theme, workloadWidth, "Workload", []string{
		stateText(*selected),
		shortImageRef(selected.Image),
		defaultText(selected.Runtime, "unknown") + " runtime",
		modernStorageSummary(*selected),
	})
	topology := workload
	if selected.DevContainers {
		developmentRenderWidth := developmentWidth
		if developmentRenderWidth == 0 {
			developmentRenderWidth = inner
		}
		development := renderTopologyNode(theme, developmentRenderWidth, "Development", []string{
			featureState(selected.State, "IDE environment"),
			defaultText(shortImageRef(selected.DevContainersImage), "curated IDE image"),
			featureState(selected.State, "SSH"),
			formatMiBHuman(selected.DevContainersDiskMiB) + " IDE disk",
			"└ Podman Dev Containers",
		})
		if developmentWidth > 0 {
			topology = lipgloss.JoinHorizontal(lipgloss.Top, workload, "  ", development)
		} else {
			topology += "\n" + development
		}
	}

	network := "offline"
	if selected.Net {
		network = "↓ " + formatNetworkBytes(selected.RXBytes) + "  ↑ " + formatNetworkBytes(selected.TXBytes)
	}
	access := "SSH disabled"
	if selected.SSH {
		access = featureState(selected.State, "SSH")
	}
	facts := []string{
		separator,
		joinSides(lipgloss.NewStyle().Foreground(theme.muted).Render("Network"), lipgloss.NewStyle().Foreground(theme.secondary).Render(network), inner),
		joinSides(lipgloss.NewStyle().Foreground(theme.muted).Render("Access"), lipgloss.NewStyle().Foreground(theme.secondary).Render(access), inner),
		joinSides(lipgloss.NewStyle().Foreground(theme.muted).Render("Attached"), lipgloss.NewStyle().Foreground(theme.secondary).Render(strings.Join([]string{pluralCount(selected.Shares, "mount"), pluralCount(selected.Ports, "port"), pluralCount(selected.SecretCount, "secret")}, " · ")), inner),
	}
	if !selected.Updated.IsZero() {
		facts = append(facts, joinSides(lipgloss.NewStyle().Foreground(theme.muted).Render("Configured"), lipgloss.NewStyle().Foreground(theme.secondary).Render(formatConfigTime(selected.Updated)), inner))
	}
	content := header + "\n" + separator + "\n" + lipgloss.NewStyle().Foreground(theme.secondary).Render(truncateText(vmSummary, inner)) + "\n\n" + topology + "\n\n" + strings.Join(facts, "\n")
	content = sliceBlockLines(content, 0, maxInt(1, height-2))
	style := lipgloss.NewStyle().Foreground(theme.text).Background(theme.panel).Border(lipgloss.RoundedBorder()).BorderForeground(theme.borderMuted).Padding(0, 1).Width(width).Height(height).MaxHeight(height)
	return renderSurface(style, theme.text, theme.panel, content)
}

func renderTopologyNode(theme tuiTheme, width int, title string, rows []string) string {
	if width <= 0 {
		return ""
	}
	inner := maxInt(4, width-4)
	lines := []string{lipgloss.NewStyle().Bold(true).Foreground(theme.accent).Render(truncateText(title, inner))}
	for index, row := range rows {
		style := lipgloss.NewStyle().Foreground(theme.secondary)
		if index == 0 {
			style = style.Foreground(theme.success)
		}
		lines = append(lines, style.Render(truncateText(row, inner)))
	}
	content := strings.Join(lines, "\n")
	height := maxInt(7, len(lines)+2)
	style := lipgloss.NewStyle().Foreground(theme.text).Background(theme.panelRaised).Border(lipgloss.RoundedBorder()).BorderForeground(theme.border).Padding(0, 1).Width(width).Height(height).MaxHeight(height)
	return renderSurface(style, theme.text, theme.panelRaised, content)
}

func sandboxStateColor(theme tuiTheme, state dashboardapi.SandboxState) color.Color {
	switch state {
	case tuiRunning:
		return theme.success
	case tuiStarting:
		return theme.warning
	default:
		return theme.muted
	}
}

func stateText(sandbox tuiSandbox) string {
	switch sandbox.State {
	case tuiRunning:
		return "● Running"
	case tuiStarting:
		return "◐ Starting"
	default:
		return "○ Stopped"
	}
}

func featureState(state dashboardapi.SandboxState, label string) string {
	if state == tuiRunning {
		return "● " + label + " ready"
	}
	return "○ " + label + " configured"
}

func modernStorageSummary(sandbox tuiSandbox) string {
	if !sandbox.RW {
		return "read-only workload root"
	}
	if sandbox.DiskSizeMiB == 0 {
		return "persistent writable disk"
	}
	return formatMiBHuman(sandbox.DiskSizeMiB) + " persistent writable disk"
}

func sandboxFeatureSummary(sandbox tuiSandbox) string {
	var features []string
	if sandbox.SSH {
		features = append(features, "SSH")
	}
	if sandbox.DevContainers {
		features = append(features, "Dev Containers")
	}
	if len(features) == 0 {
		features = append(features, "standard workload")
	}
	if sandbox.Ports > 0 {
		features = append(features, pluralCount(sandbox.Ports, "port"))
	}
	return strings.Join(features, " · ")
}

func shortImageRef(ref string) string {
	ref = strings.TrimPrefix(ref, "docker.io/library/")
	ref = strings.TrimPrefix(ref, "docker.io/")
	return defaultText(ref, "image unavailable")
}

func formatNetworkBytes(value uint64) string {
	const (
		kiB = uint64(1 << 10)
		miB = uint64(1 << 20)
		giB = uint64(1 << 30)
	)
	switch {
	case value >= giB:
		return fmt.Sprintf("%.1f GiB", float64(value)/float64(giB))
	case value >= miB:
		return fmt.Sprintf("%.1f MiB", float64(value)/float64(miB))
	case value >= kiB:
		return fmt.Sprintf("%.1f KiB", float64(value)/float64(kiB))
	default:
		return fmt.Sprintf("%d B", value)
	}
}

func pluralCount(value int, singular string) string {
	suffix := "s"
	if value == 1 {
		suffix = ""
	}
	return fmt.Sprintf("%d %s%s", value, singular, suffix)
}

func formatMiBHuman(value uint) string {
	if value == 0 {
		return "—"
	}
	if value >= 1024 {
		if value%1024 == 0 {
			return fmt.Sprintf("%d GiB", value/1024)
		}
		return fmt.Sprintf("%.1f GiB", float64(value)/1024)
	}
	return fmt.Sprintf("%d MiB", value)
}

func renderListScrollbar(theme tuiTheme, height, count, visible, scroll int) string {
	if count <= visible || height < 2 {
		return ""
	}
	thumbHeight := maxInt(1, height*visible/count)
	thumbTop := (height - thumbHeight) * scroll / maxInt(1, count-visible)
	lines := make([]string, height)
	for index := range lines {
		glyph, foreground := "│", theme.borderMuted
		if index >= thumbTop && index < thumbTop+thumbHeight {
			glyph, foreground = "┃", theme.accent
		}
		lines[index] = lipgloss.NewStyle().Foreground(foreground).Background(theme.bg).Render(glyph)
	}
	return strings.Join(lines, "\n")
}

func formatConfigTime(value time.Time) string {
	if value.IsZero() {
		return "unknown"
	}
	return value.Local().Format("2006-01-02 15:04")
}
