package dashboard

import (
	"fmt"
	"image/color"
	"sort"
	"strings"
	"time"

	dashboardapi "github.com/ejpir/gantry/internal/dashboard/api"

	"charm.land/lipgloss/v2"
)

const (
	tuiOverviewTrafficWidth = 40
	tuiOverviewDeniedWidth  = 30
	tuiOverviewContentSlack = 2
)

type tuiOverviewGeometry struct {
	panelWidth, panelHeight int
	gap, visible            int
	start, end              int
	entryRects              map[int]tuiRect
}

type tuiOperationalPanelContent struct {
	header, traffic, denied, exposure, recent string
}

const (
	tuiMasterItemHeight = 4
	tuiMasterItemGap    = 1
)

type tuiMasterDetailGeometry struct {
	listWidth, detailWidth          int
	workloadWidth, developmentWidth int
	visible, start, end             int
	workloadRect, createRect        tuiRect
	entryRects                      map[int]tuiRect
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
	return m.page == tuiSandboxesPage && layout.width >= 78 && layout.contentHeight >= 23 && !m.loading
}

func (m sandboxTUIModel) overviewGeometry(layout tuiDashboardLayout) tuiOverviewGeometry {
	availableWidth := maxInt(20, layout.width-4)
	preferredWidth := m.overviewPreferredPanelWidth(tuiThemeFor(m.dark))
	geometry := tuiOverviewGeometry{
		panelWidth:  minInt(availableWidth, preferredWidth),
		panelHeight: 9,
		gap:         1,
		entryRects:  make(map[int]tuiRect),
	}
	if geometry.panelWidth < 96 {
		geometry.panelHeight = 11
	}
	geometry.visible = maxInt(1, (layout.contentHeight+geometry.gap)/(geometry.panelHeight+geometry.gap))
	geometry.start = clampInt(m.scrollRow, 0, maxInt(0, len(m.sandboxes)-geometry.visible))
	geometry.end = minInt(len(m.sandboxes), geometry.start+geometry.visible)
	for index := geometry.start; index < geometry.end; index++ {
		geometry.entryRects[index] = tuiRect{
			x: layout.contentX + 2,
			y: layout.contentY + (index-geometry.start)*(geometry.panelHeight+geometry.gap),
			w: geometry.panelWidth,
			h: geometry.panelHeight,
		}
	}
	return geometry
}

func (m sandboxTUIModel) masterDetailGeometry(layout tuiDashboardLayout) tuiMasterDetailGeometry {
	geometry := tuiMasterDetailGeometry{entryRects: make(map[int]tuiRect)}
	geometry.listWidth = clampInt(layout.width/4, 30, 40)
	geometry.detailWidth = maxInt(38, layout.width-geometry.listWidth-1)
	detailInner := maxInt(12, geometry.detailWidth-4)
	geometry.workloadWidth = detailInner
	if selected := m.selected(); selected != nil && selected.DevContainers && detailInner >= 62 {
		geometry.workloadWidth = (detailInner - 2) / 2
		geometry.developmentWidth = detailInner - geometry.workloadWidth - 2
	}
	if m.selected() != nil {
		geometry.workloadRect = tuiRect{
			x: layout.contentX + geometry.listWidth + 3,
			y: layout.contentY + 5,
			w: geometry.workloadWidth,
			h: topologyNodeHeight(4),
		}
	} else if m.onNewCard() {
		geometry.createRect = tuiRect{
			x: layout.contentX + geometry.listWidth + 1,
			y: layout.contentY,
			w: geometry.detailWidth,
			h: layout.contentHeight,
		}
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
		empty := lipgloss.JoinVertical(lipgloss.Center,
			lipgloss.NewStyle().Bold(true).Foreground(theme.text).Render("No sandboxes"),
			lipgloss.NewStyle().Foreground(theme.secondary).Render("Press n to create one."),
		)
		style := lipgloss.NewStyle().Foreground(theme.text).Background(theme.bg).Width(layout.width).Height(layout.contentHeight).Align(lipgloss.Center, lipgloss.Center)
		return renderSurface(style, theme.text, theme.bg, empty)
	}

	geometry := m.overviewGeometry(layout)
	panels := make([]string, 0, geometry.end-geometry.start)
	for index := geometry.start; index < geometry.end; index++ {
		panels = append(panels, m.renderOperationalSandboxPanel(theme, geometry.panelWidth, geometry.panelHeight, m.sandboxes[index], index == m.cursor))
	}
	content := strings.Join(panels, strings.Repeat("\n", geometry.gap+1))
	style := lipgloss.NewStyle().Foreground(theme.text).Background(theme.bg).Padding(0, 2).Width(layout.width).Height(layout.contentHeight).MaxHeight(layout.contentHeight)
	return renderSurface(style, theme.text, theme.bg, content)
}

func (m sandboxTUIModel) overviewNavigationCapacity(layout tuiDashboardLayout) int {
	return maxInt(1, m.overviewGeometry(layout).visible)
}

func (m sandboxTUIModel) renderOperationalSandboxPanel(theme tuiTheme, width, height int, sandbox tuiSandbox, selected bool) string {
	border, background := theme.borderMuted, theme.bg
	if selected {
		border = theme.accent
	}
	inner := maxInt(12, width-4)
	panel := m.operationalPanelContent(theme, sandbox)
	lines := []string{truncateANSI(panel.header, inner), ""}
	if width >= 96 {
		trafficWidth := minInt(tuiOverviewTrafficWidth, maxInt(8, inner))
		deniedWidth := minInt(tuiOverviewDeniedWidth, maxInt(8, inner-trafficWidth))
		details := tableCell(panel.traffic, trafficWidth) + tableCell(panel.denied, deniedWidth) + truncateANSI(panel.exposure, maxInt(1, inner-trafficWidth-deniedWidth))
		lines = append(lines, details, "", truncateANSI("  "+panel.recent, inner))
	} else {
		lines = append(lines, truncateANSI(panel.traffic, inner), truncateANSI(panel.denied, inner), truncateANSI(panel.exposure, inner), "", truncateANSI("  "+panel.recent, inner))
	}
	content := strings.Join(lines, "\n")
	style := lipgloss.NewStyle().Foreground(theme.text).Background(background).Border(lipgloss.NormalBorder()).BorderForeground(border).Padding(1, 1).Width(width).Height(height).MaxHeight(height)
	return renderSurface(style, theme.text, background, content)
}

func (m sandboxTUIModel) operationalPanelContent(theme tuiTheme, sandbox tuiSandbox) tuiOperationalPanelContent {
	state := lipgloss.NewStyle().Foreground(sandboxStateColor(theme, sandbox.State)).Render("●")
	name := lipgloss.NewStyle().Bold(true).Foreground(theme.text).Render(sandbox.Name)
	metadata := fmt.Sprintf("%dc %s · %s · %s", maxInt(1, sandbox.VCPUs), formatOverviewMemory(sandbox.MemMB), defaultText(sandbox.Runtime, "runtime unknown"), shortImageRef(sandbox.Image))
	header := state + " " + name + "  " + lipgloss.NewStyle().Foreground(theme.muted).Render(metadata)
	traffic := lipgloss.NewStyle().Foreground(theme.muted).Render("traffic  ") +
		lipgloss.NewStyle().Foreground(theme.success).Render(m.sandboxTrafficSparkline(sandbox.Name, 16)) +
		lipgloss.NewStyle().Foreground(theme.secondary).Render("  ↑"+formatBytes(sandbox.TXBytes)+" ↓"+formatBytes(sandbox.RXBytes))
	denied := lipgloss.NewStyle().Foreground(theme.muted).Render("denied   ") +
		lipgloss.NewStyle().Foreground(theme.error).Render(formatDashboardCount(sandbox.DroppedPackets))
	if last := m.lastDeniedAt(sandbox.Name); !last.IsZero() {
		denied += lipgloss.NewStyle().Foreground(theme.muted).Render(" last " + formatOverviewDenyClock(last))
	}
	return tuiOperationalPanelContent{
		header:   header,
		traffic:  traffic,
		denied:   denied,
		exposure: m.sandboxExposure(theme, sandbox),
		recent:   lipgloss.NewStyle().Foreground(theme.muted).Render("recent denies: ") + m.recentDeniedHosts(theme, sandbox.Name, 4),
	}
}

func (m sandboxTUIModel) overviewPreferredPanelWidth(theme tuiTheme) int {
	preferredInner := 92
	for _, sandbox := range m.sandboxes {
		panel := m.operationalPanelContent(theme, sandbox)
		preferredInner = maxInt(preferredInner, lipgloss.Width(panel.header))
		preferredInner = maxInt(preferredInner, tuiOverviewTrafficWidth+tuiOverviewDeniedWidth+lipgloss.Width(panel.exposure))
		preferredInner = maxInt(preferredInner, lipgloss.Width("  "+panel.recent))
	}
	// Two border cells and two horizontal padding cells surround the content.
	return preferredInner + tuiOverviewContentSlack + 4
}

func formatOverviewMemory(mib uint) string {
	if mib >= 1024 {
		return fmt.Sprintf("%.0fG", float64(mib)/1024)
	}
	return fmt.Sprintf("%dM", mib)
}

func formatOverviewDenyClock(value time.Time) string {
	if value.IsZero() {
		return "—"
	}
	if time.Since(value) < 24*time.Hour {
		return value.Local().Format("15:04")
	}
	return value.Local().Format("Jan02 15")
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

func (m sandboxTUIModel) sandboxExposure(theme tuiTheme, sandbox tuiSandbox) string {
	mounts, writable := 0, 0
	for _, mount := range m.mounts {
		if mount.Sandbox != sandbox.Name {
			continue
		}
		mounts++
		if !mount.ReadOnly {
			writable++
		}
	}
	if mounts == 0 {
		mounts = sandbox.Shares
	}
	value := pluralCount(sandbox.Ports, "port") + " · " + pluralCount(mounts, "mount")
	if writable > 0 {
		value += " " + lipgloss.NewStyle().Foreground(theme.warning).Render(fmt.Sprintf("%d rw", writable))
	} else if mounts > 0 {
		value += lipgloss.NewStyle().Foreground(theme.muted).Render(" ro")
	}
	return lipgloss.NewStyle().Foreground(theme.muted).Render("exposure ") + lipgloss.NewStyle().Foreground(theme.secondary).Render(value)
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

func (m sandboxTUIModel) recentDeniedHosts(theme tuiTheme, sandbox string, limit int) string {
	type deniedHost struct {
		host string
		at   time.Time
	}
	byHost := make(map[string]time.Time)
	for _, row := range m.traffic {
		if row.Sandbox != sandbox || row.Allowed {
			continue
		}
		host := defaultText(row.Host, row.Address)
		if host == "" || (!row.LastSeen.IsZero() && !row.LastSeen.After(byHost[host])) {
			continue
		}
		byHost[host] = row.LastSeen
	}
	hosts := make([]deniedHost, 0, len(byHost))
	for host, at := range byHost {
		hosts = append(hosts, deniedHost{host: host, at: at})
	}
	sort.Slice(hosts, func(left, right int) bool { return hosts[left].at.After(hosts[right].at) })
	if len(hosts) > limit {
		hosts = hosts[:limit]
	}
	if len(hosts) == 0 {
		return lipgloss.NewStyle().Foreground(theme.muted).Render("none")
	}
	values := make([]string, len(hosts))
	for index, host := range hosts {
		values[index] = lipgloss.NewStyle().Foreground(theme.secondary).Render(host.host)
		if host.host == "ff02::2" || host.host == "ff02::16" {
			values[index] += " " + lipgloss.NewStyle().Foreground(theme.muted).Render("(ipv6 multicast, built-in)")
		}
	}
	return strings.Join(values, lipgloss.NewStyle().Foreground(theme.muted).Render(" · "))
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
	detail := m.renderSandboxTopology(theme, geometry, layout.contentHeight)
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
		if index > geometry.start {
			lines = append(lines, "")
		}
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

func (m sandboxTUIModel) renderSandboxTopology(theme tuiTheme, geometry tuiMasterDetailGeometry, height int) string {
	width := geometry.detailWidth
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

	workloadWidth := geometry.workloadWidth
	developmentWidth := geometry.developmentWidth
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
	factsInner := maxInt(8, inner-4)
	factsSeparator := lipgloss.NewStyle().Foreground(theme.borderMuted).Render(strings.Repeat("─", factsInner))
	facts := []string{
		factsSeparator,
		joinSides(lipgloss.NewStyle().Foreground(theme.muted).Render("Network"), lipgloss.NewStyle().Foreground(theme.secondary).Render(network), factsInner),
		joinSides(lipgloss.NewStyle().Foreground(theme.muted).Render("Access"), lipgloss.NewStyle().Foreground(theme.secondary).Render(access), factsInner),
		joinSides(lipgloss.NewStyle().Foreground(theme.muted).Render("Attached"), lipgloss.NewStyle().Foreground(theme.secondary).Render(strings.Join([]string{pluralCount(selected.Shares, "mount"), pluralCount(selected.Ports, "port"), pluralCount(selected.SecretCount, "secret")}, " · ")), factsInner),
	}
	if !selected.Updated.IsZero() {
		facts = append(facts, joinSides(lipgloss.NewStyle().Foreground(theme.muted).Render("Configured"), lipgloss.NewStyle().Foreground(theme.secondary).Render(formatConfigTime(selected.Updated)), factsInner))
	}
	factsStyle := lipgloss.NewStyle().Foreground(theme.secondary).Background(theme.panel).Padding(1, 2).Width(inner)
	factsBlock := renderSurface(factsStyle, theme.secondary, theme.panel, strings.Join(facts, "\n"))
	content := header + "\n" + separator + "\n" + lipgloss.NewStyle().Foreground(theme.secondary).Render(truncateText(vmSummary, inner)) + "\n\n" + topology + "\n" + factsBlock
	content = sliceBlockLines(content, 0, maxInt(1, height-2))
	style := lipgloss.NewStyle().Foreground(theme.text).Background(theme.panel).Border(lipgloss.RoundedBorder()).BorderForeground(theme.borderMuted).Padding(0, 1).Width(width).Height(height).MaxHeight(height)
	return renderSurface(style, theme.text, theme.panel, content)
}

func renderTopologyNode(theme tuiTheme, width int, title string, rows []string) string {
	if width <= 0 {
		return ""
	}
	inner := maxInt(4, width-4)
	lines := []string{lipgloss.NewStyle().Bold(true).Foreground(theme.accent).Render(truncateText(title, inner)), ""}
	for index, row := range rows {
		style := lipgloss.NewStyle().Foreground(theme.secondary)
		if index == 0 {
			style = style.Foreground(theme.success)
		}
		lines = append(lines, style.Render(truncateText(row, inner)))
	}
	lines = append(lines, "")
	content := strings.Join(lines, "\n")
	height := topologyNodeHeight(len(rows))
	style := lipgloss.NewStyle().Foreground(theme.text).Background(theme.panelRaised).Border(lipgloss.RoundedBorder()).BorderForeground(theme.border).Padding(0, 1).Width(width).Height(height).MaxHeight(height)
	return renderSurface(style, theme.text, theme.panelRaised, content)
}

func topologyNodeHeight(rows int) int {
	return maxInt(9, rows+5) // title, rows, borders, and one padding row on each side
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
