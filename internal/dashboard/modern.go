package dashboard

import (
	"fmt"
	"image/color"
	"strings"
	"time"

	dashboardapi "github.com/ejpir/gantry/internal/dashboard/api"

	"charm.land/lipgloss/v2"
)

const (
	tuiOverviewPanelWidth        = 112
	tuiOverviewColumnsMinWidth   = 78
	tuiOverviewInspectorMinWidth = 140
	tuiOverviewInspectorWidth    = 40
	tuiOverviewInspectorHeight   = 25
)

type tuiOverviewGeometry struct {
	panelWidth, panelHeight int
	gap, visible            int
	start, end              int
	entryRects              map[int]tuiRect
	inspectorRect           tuiRect
}

type tuiOperationalPanelContent struct {
	name, metadata, resources           string
	traffic, denied, access             string
	trafficNote, deniedNote, accessNote string
	recent                              string
}

const (
	tuiMasterItemHeight = 4
	tuiMasterItemGap    = 1
)

type tuiMasterDetailGeometry struct {
	listWidth, detailWidth, detailOffset int
	detailTop                            int
	visible, start, end                  int
	entryRects                           map[int]tuiRect
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

func (m sandboxTUIModel) usesMasterDetail(layout tuiDashboardLayout) bool {
	return m.page == tuiSandboxesPage && layout.width >= 78 && layout.contentHeight >= tuiStackMinHeight && !m.loading
}

func (m sandboxTUIModel) overviewGeometry(layout tuiDashboardLayout) tuiOverviewGeometry {
	availableWidth := maxInt(20, layout.width-4)
	geometry := tuiOverviewGeometry{
		panelWidth:  minInt(availableWidth, tuiOverviewPanelWidth),
		panelHeight: 12,
		gap:         1,
		entryRects:  make(map[int]tuiRect),
	}
	if layout.width >= tuiOverviewInspectorMinWidth && layout.contentHeight >= tuiOverviewInspectorHeight && !m.loading && m.selected() != nil {
		geometry.panelWidth = minInt(geometry.panelWidth, availableWidth-tuiOverviewInspectorWidth-2)
		geometry.inspectorRect = tuiRect{
			x: layout.contentX + 2 + geometry.panelWidth + 2,
			y: layout.contentY,
			w: tuiOverviewInspectorWidth,
			h: tuiOverviewInspectorHeight,
		}
	}
	if geometry.panelWidth < tuiOverviewColumnsMinWidth {
		geometry.panelHeight = 13
	}
	geometry.panelHeight = minInt(geometry.panelHeight, layout.contentHeight)
	geometry.visible = maxInt(1, (layout.contentHeight+geometry.gap)/(geometry.panelHeight+geometry.gap))
	geometry.start = clampInt(m.scrollRow, 0, maxInt(0, len(m.sandboxes)-geometry.visible))
	geometry.end = minInt(len(m.sandboxes), geometry.start+geometry.visible)
	for index := geometry.start; index < geometry.end; index++ {
		rect := tuiRect{
			x: layout.contentX + 2,
			y: layout.contentY + (index-geometry.start)*(geometry.panelHeight+geometry.gap),
			w: geometry.panelWidth,
			h: geometry.panelHeight,
		}
		viewport := tuiRect{x: layout.contentX, y: layout.contentY, w: layout.width, h: layout.contentHeight}
		if visible, ok := intersectRect(rect, viewport); ok {
			geometry.entryRects[index] = visible
		}
	}
	return geometry
}

func (m sandboxTUIModel) masterDetailGeometry(layout tuiDashboardLayout) tuiMasterDetailGeometry {
	geometry := tuiMasterDetailGeometry{entryRects: make(map[int]tuiRect)}
	geometry.listWidth = clampInt(layout.width/4, 30, 36)
	availableWidth := maxInt(38, layout.width-geometry.listWidth-2)
	geometry.detailWidth = minInt(availableWidth, tuiStackMaxWidth)
	geometry.detailOffset = geometry.listWidth + 2 + (availableWidth-geometry.detailWidth)/2
	// Align the detail heading with the sidebar heading, not its top border.
	// Retain the last data row on the shortest master-detail layouts.
	if layout.contentHeight > tuiStackMinHeight {
		geometry.detailTop = 1
	}
	available := maxInt(1, layout.contentHeight-4)
	geometry.visible = maxInt(1, (available+tuiMasterItemGap)/(tuiMasterItemHeight+tuiMasterItemGap))
	geometry.start = clampInt(m.scrollRow, 0, maxInt(0, m.entryCount()-geometry.visible))
	geometry.end = minInt(m.entryCount(), geometry.start+geometry.visible)
	for index := geometry.start; index < geometry.end; index++ {
		geometry.entryRects[index] = tuiRect{
			x: layout.contentX + 2,
			y: layout.contentY + 3 + (index-geometry.start)*(tuiMasterItemHeight+tuiMasterItemGap),
			w: maxInt(1, geometry.listWidth-4),
			h: tuiMasterItemHeight,
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
	if len(m.sandboxes) == 0 {
		title, description := "No sandboxes", "Press n to create one."
		if m.sandboxFilter != "" {
			title, description = "No matching sandboxes", "Press / to change or clear the filter."
		}
		lines := []string{
			lipgloss.NewStyle().Bold(true).Foreground(theme.text).Render(truncateText(title, maxInt(1, layout.width-4))),
			lipgloss.NewStyle().Foreground(theme.secondary).Render(truncateText(description, maxInt(1, layout.width-4))),
		}
		if layout.contentHeight >= 9 {
			lines = append([]string{renderLogo(theme), ""}, lines...)
		}
		empty := lipgloss.JoinVertical(lipgloss.Center, lines...)
		style := lipgloss.NewStyle().Foreground(theme.text).Background(theme.bg).Width(layout.width).Height(layout.contentHeight).Align(lipgloss.Center, lipgloss.Center)
		return renderSurface(style, theme.text, theme.bg, empty)
	}

	geometry := m.overviewGeometry(layout)
	panels := make([]string, 0, geometry.end-geometry.start)
	for index := geometry.start; index < geometry.end; index++ {
		panels = append(panels, m.renderOperationalSandboxPanel(theme, geometry.panelWidth, geometry.panelHeight, m.sandboxes[index], index == m.cursor))
	}
	content := strings.Join(panels, strings.Repeat("\n", geometry.gap+1))
	if geometry.inspectorRect.w > 0 {
		inspector, _ := m.renderOverviewInspector(theme, geometry.inspectorRect)
		content = lipgloss.JoinHorizontal(lipgloss.Top, content, "  ", inspector)
	}
	style := lipgloss.NewStyle().Foreground(theme.text).Background(theme.bg).Padding(0, 2).Width(layout.width).Height(layout.contentHeight).MaxHeight(layout.contentHeight)
	return renderSurface(style, theme.text, theme.bg, content)
}

func (m sandboxTUIModel) overviewNavigationCapacity(layout tuiDashboardLayout) int {
	return maxInt(1, m.overviewGeometry(layout).visible)
}

func (m sandboxTUIModel) renderOperationalSandboxPanel(theme tuiTheme, width, height int, sandbox tuiSandbox, selected bool) string {
	border, background := theme.borderMuted, theme.panel
	if selected {
		border, background = theme.accent, theme.panelSelected
	}
	inner := maxInt(1, width-4)
	panel := m.operationalPanelContent(theme, sandbox)
	marker := "  "
	if selected {
		marker = lipgloss.NewStyle().Foreground(theme.accent).Render("› ")
	}
	state := m.renderSandboxState(theme, sandbox)
	muted := lipgloss.NewStyle().Foreground(theme.muted)
	label := func(text string) string { return muted.Render(text) }
	headerRight := state
	if width >= tuiOverviewColumnsMinWidth {
		headerRight += "   " + panel.resources
	}
	header := joinSides(marker+panel.name, headerRight, inner)
	lines := []string{header, panel.metadata}
	paddingY := 1
	switch {
	case height < 12:
		paddingY = 0
		lines = append(lines,
			panel.resources,
			label("Traffic  ")+panel.traffic,
			label("Blocked  ")+panel.denied,
			label("Access   ")+panel.access,
			panel.recent,
		)
	case width >= tuiOverviewColumnsMinWidth:
		trafficWidth := maxInt(24, (inner-4)*2/5)
		deniedWidth := 19
		accessWidth := inner - trafficWidth - deniedWidth - 4
		columns := func(traffic, denied, access string) string {
			return tableCell(traffic, trafficWidth) + "  " + tableCell(denied, deniedWidth) + "  " + tableCell(access, accessWidth)
		}
		lines = append(lines, "",
			columns(label("TRAFFIC TOTALS"), label("BLOCKED PACKETS"), label("ACCESS")),
			columns(panel.traffic, panel.denied, panel.access),
			columns(panel.trafficNote, panel.deniedNote, panel.accessNote),
			"", panel.recent,
		)
	default:
		lines = append(lines, panel.resources, "",
			label("Traffic  ")+panel.traffic,
			label("Blocked  ")+panel.denied+"  "+panel.deniedNote,
			label("Access   ")+panel.access+"  "+panel.accessNote,
			"", panel.recent,
		)
	}
	for i := range lines {
		lines[i] = truncateANSI(lines[i], inner)
	}
	lines = lines[:minInt(len(lines), maxInt(0, height-2-2*paddingY))]
	content := strings.Join(lines, "\n")
	style := lipgloss.NewStyle().Foreground(theme.text).Background(background).Border(lipgloss.RoundedBorder()).BorderForeground(border).Padding(paddingY, 1).Width(width).Height(height).MaxHeight(height)
	return renderSurface(style, theme.text, background, content)
}

func (m sandboxTUIModel) operationalPanelContent(theme tuiTheme, sandbox tuiSandbox) tuiOperationalPanelContent {
	muted := lipgloss.NewStyle().Foreground(theme.muted)
	value := lipgloss.NewStyle().Bold(true).Foreground(theme.text)
	blockedColor := theme.muted
	if sandbox.DroppedPackets > 0 {
		blockedColor = theme.error
	}
	last := "no blocks recorded"
	if at := m.lastDeniedAt(sandbox.Name); !at.IsZero() {
		last = "last " + formatOverviewDenyClock(at)
	} else if sandbox.DroppedPackets > 0 {
		last = "time unavailable"
	}
	access, accessNote := m.overviewAccess(theme, sandbox)
	return tuiOperationalPanelContent{
		name:        value.Render(sandbox.Name),
		metadata:    muted.Render(shortImageRef(sandbox.Image) + " / " + defaultText(sandbox.Runtime, "runtime unknown")),
		resources:   muted.Render(fmt.Sprintf("%d vCPU · %s", maxInt(1, sandbox.DisplayCPUs()), formatMiBHuman(sandbox.DisplayMemoryMiB()))),
		traffic:     value.Render("↑" + formatBytes(sandbox.TXBytes) + "  ↓" + formatBytes(sandbox.RXBytes)),
		trafficNote: lipgloss.NewStyle().Foreground(theme.success).Render(m.sandboxTrafficSparkline(sandbox.Name, 12)) + muted.Render("  recent"),
		denied:      value.Foreground(blockedColor).Render(formatDashboardCount(sandbox.DroppedPackets)),
		deniedNote:  muted.Render(last),
		access:      access,
		accessNote:  accessNote,
		recent:      muted.Render("Recent blocks: ") + m.recentDeniedHosts(theme, sandbox.Name, 3),
	}
}

func formatOverviewDenyClock(value time.Time) string {
	if value.IsZero() {
		return "—"
	}
	if time.Since(value) < 24*time.Hour {
		return value.Local().Format("15:04")
	}
	return value.Local().Format("Jan 02")
}

func (m *sandboxTUIModel) sampleSandboxTraffic(sandboxes []tuiSandbox) {
	if m.trafficHistory == nil {
		m.trafficHistory = make(map[string][]uint64)
	}
	if m.trafficTotals == nil {
		m.trafficTotals = make(map[string]uint64)
	}
	present := make(map[string]struct{}, len(sandboxes))
	for _, sandbox := range sandboxes {
		present[sandbox.Name] = struct{}{}
		total := sandbox.TXBytes
		if ^uint64(0)-total < sandbox.RXBytes {
			total = ^uint64(0)
		} else {
			total += sandbox.RXBytes
		}
		previous, sampled := m.trafficTotals[sandbox.Name]
		m.trafficTotals[sandbox.Name] = total
		delta := uint64(0)
		if sampled {
			if total >= previous {
				delta = total - previous
			} else {
				delta = total
			}
		}
		history := append(m.trafficHistory[sandbox.Name], delta)
		if len(history) > 15 {
			history = append([]uint64(nil), history[len(history)-15:]...)
		}
		m.trafficHistory[sandbox.Name] = history
	}
	for name := range m.trafficTotals {
		if _, ok := present[name]; !ok {
			delete(m.trafficTotals, name)
			delete(m.trafficHistory, name)
		}
	}
}

func (m sandboxTUIModel) sandboxTrafficSparkline(sandbox string, width int) string {
	width = maxInt(1, width)
	levels := []rune("▁▂▃▄▅▆▇█")
	values := m.trafficHistory[sandbox]
	if len(values) > width {
		values = values[len(values)-width:]
	}
	var peak uint64
	for _, value := range values {
		if value > peak {
			peak = value
		}
	}
	result := make([]rune, width)
	for index := range result {
		result[index] = levels[0]
	}
	offset := width - len(values)
	for index, value := range values {
		level := 0
		if peak > 0 && value > 0 {
			level = int(float64(value) / float64(peak) * float64(len(levels)-1))
			level = clampInt(level, 1, len(levels)-1)
		}
		result[offset+index] = levels[level]
	}
	return string(result)
}

func (m sandboxTUIModel) overviewAccess(theme tuiTheme, sandbox tuiSandbox) (string, string) {
	mounts, writable, errors := 0, 0, 0
	for _, mount := range m.mounts {
		if mount.Sandbox != sandbox.Name {
			continue
		}
		mounts++
		if mount.Error != "" {
			errors++
		} else if !mount.ReadOnly {
			writable++
		}
	}
	note := "no host mounts"
	if mounts > 0 {
		note = "read-only mounts"
	}
	if mounts == 0 && sandbox.Shares > 0 {
		mounts = sandbox.Shares
		note = "mount details unavailable"
	}
	noteColor := theme.muted
	if writable > 0 {
		note, noteColor = pluralCount(writable, "writable mount"), theme.warning
	}
	if errors > 0 {
		note, noteColor = pluralCount(errors, "mount error"), theme.error
	}
	if sandbox.ConfigError {
		note, noteColor = "configuration unavailable", theme.warning
	}
	value := pluralCount(sandbox.Ports, "port") + " · " + pluralCount(mounts, "mount")
	return lipgloss.NewStyle().Bold(true).Foreground(theme.text).Render(value), lipgloss.NewStyle().Foreground(noteColor).Render(note)
}

func (m sandboxTUIModel) lastDeniedAt(sandbox string) time.Time {
	var latest time.Time
	for _, row := range m.traffic {
		if row.Sandbox == sandbox && !row.Allowed && row.LastSeen.After(latest) {
			latest = row.LastSeen
		}
	}
	return latest
}

func formatDashboardCount(value uint64) string {
	raw := fmt.Sprint(value)
	for index := len(raw) - 3; index > 0; index -= 3 {
		raw = raw[:index] + "," + raw[index:]
	}
	return raw
}

func (m sandboxTUIModel) renderSandboxMasterDetail(theme tuiTheme, layout tuiDashboardLayout) string {
	geometry := m.masterDetailGeometry(layout)
	list := m.renderSandboxMasterList(theme, geometry, layout.contentHeight)
	detail := strings.Repeat("\n", geometry.detailTop) + m.renderSandboxTopology(theme, geometry, layout.contentHeight-geometry.detailTop)
	return lipgloss.JoinHorizontal(lipgloss.Top, list, strings.Repeat(" ", geometry.detailOffset-geometry.listWidth), detail)
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
	appendEntry := func(entry []string, selected bool) {
		background := theme.panel
		if selected {
			background = theme.panelSelected
		}
		style := lipgloss.NewStyle().Foreground(theme.secondary).Background(background).
			Width(inner).Height(tuiMasterItemHeight).MaxHeight(tuiMasterItemHeight)
		lines = append(lines, renderSurface(style, theme.secondary, background, strings.Join(entry, "\n")))
	}
	for index := geometry.start; index < geometry.end; index++ {
		if index > geometry.start {
			lines = append(lines, "")
		}
		if index == len(m.sandboxes) {
			line := lipgloss.NewStyle().Foreground(theme.accent).Render("＋") + " " + lipgloss.NewStyle().Bold(true).Foreground(theme.text).Render("New sandbox")
			if index == m.cursor {
				line = lipgloss.NewStyle().Foreground(theme.accent).Render("▌") + truncateANSI(line, inner-1)
			} else {
				line = " " + line
			}
			appendEntry([]string{line, lipgloss.NewStyle().Foreground(theme.muted).Render("  n / enter to create"), "", ""}, index == m.cursor)
			continue
		}
		sandbox := m.sandboxes[index]
		state := lipgloss.NewStyle().Foreground(sandboxStateColor(theme, sandbox.State)).Render(strings.Fields(stateText(sandbox))[0])
		nameStyle := lipgloss.NewStyle().Bold(true).Foreground(theme.text)
		if index == m.cursor {
			nameStyle = nameStyle.Foreground(theme.accent)
		}
		name := nameStyle.Render(truncateText(sandbox.Name, maxInt(4, inner-4)))
		first := state + " " + name
		if index == m.cursor {
			first = lipgloss.NewStyle().Foreground(theme.accent).Render("▌") + truncateANSI(first, inner-1)
		} else {
			first = " " + first
		}
		image := "  " + lipgloss.NewStyle().Foreground(theme.secondary).Render(truncateText(shortImageRef(sandbox.Image), maxInt(4, inner-2)))
		resources := fmt.Sprintf("  %d vCPU · %s", maxInt(1, sandbox.DisplayCPUs()), formatMiBHuman(sandbox.DisplayMemoryMiB()))
		features := "  " + sandboxFeatureSummary(sandbox)
		appendEntry([]string{first, image, lipgloss.NewStyle().Foreground(theme.muted).Render(truncateText(resources, inner)), lipgloss.NewStyle().Foreground(theme.muted).Render(truncateText(features, inner))}, index == m.cursor)
	}
	content := strings.Join(lines, "\n")
	style := lipgloss.NewStyle().Foreground(theme.secondary).Background(theme.panel).Border(lipgloss.RoundedBorder()).BorderForeground(theme.borderMuted).Padding(0, 1).Width(width).Height(height).MaxHeight(height)
	return renderSurface(style, theme.secondary, theme.panel, content)
}

func (m sandboxTUIModel) renderSandboxTopology(theme tuiTheme, geometry tuiMasterDetailGeometry, height int) string {
	content, _ := m.renderSandboxStack(theme, geometry.detailWidth, height)
	return content
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
