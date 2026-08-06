package sandbox

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"charm.land/lipgloss/v2"
)

const tuiTableHeaderHeight = 2

func pageTitle(page tuiPage) string {
	switch page {
	case tuiTrafficPage:
		return "TRAFFIC"
	case tuiRulesPage:
		return "RULES"
	case tuiMountsPage:
		return "MOUNTS"
	case tuiPortsPage:
		return "PORTS"
	default:
		return "SANDBOXES"
	}
}

func (m sandboxTUIModel) pageRowCount(page tuiPage) int {
	switch page {
	case tuiTrafficPage:
		return len(m.traffic)
	case tuiRulesPage:
		return len(m.rules)
	case tuiMountsPage:
		return len(m.mounts)
	case tuiPortsPage:
		return len(m.ports)
	default:
		return len(m.sandboxes)
	}
}

func (m sandboxTUIModel) tableDetailHeight() int {
	if m.dashboardLayout().contentHeight >= 12 {
		return 5
	}
	return 0
}

func (m sandboxTUIModel) tableVisibleRows() int {
	layout := m.dashboardLayout()
	return maxInt(1, layout.contentHeight-tuiTableHeaderHeight-m.tableDetailHeight())
}

func (m sandboxTUIModel) renderTrafficView(theme tuiTheme, layout tuiDashboardLayout) string {
	if m.loading {
		return m.renderTableLoading(theme, layout, "Loading network traffic…")
	}
	if len(m.traffic) == 0 {
		if names := m.sandboxesMissingTrafficCapture(); len(names) > 0 {
			return m.renderTableEmpty(theme, layout, "Restart required for traffic capture", "Stop and start "+strings.Join(names, ", ")+" once with this Gantry build, then run network commands again.")
		}
		return m.renderTableEmpty(theme, layout, "No network traffic recorded", "Traffic appears here after a network-enabled sandbox sends packets.")
	}
	inner := maxInt(1, layout.width-4)
	lines := []string{m.renderTrafficHeader(theme, inner), m.renderTableSeparator(theme, inner)}
	end := minInt(len(m.traffic), m.trafficScroll+m.tableVisibleRows())
	for index := m.trafficScroll; index < end; index++ {
		line := m.renderTrafficRow(theme, m.traffic[index], inner)
		lines = append(lines, renderTableSelection(theme, line, inner, index == m.trafficCursor))
	}
	lines = m.appendTableDetail(lines, m.renderTrafficDetail(theme, inner), layout.contentHeight)
	return renderTableSurface(theme, layout, lines)
}

func (m sandboxTUIModel) sandboxesMissingTrafficCapture() []string {
	var names []string
	for _, sandbox := range m.sandboxes {
		if sandbox.State == tuiRunning && sandbox.Net && !sandbox.TrafficAvailable {
			names = append(names, sandbox.Name)
		}
	}
	return names
}

func (m sandboxTUIModel) renderTrafficHeader(theme tuiTheme, width int) string {
	style := lipgloss.NewStyle().Bold(true).Foreground(theme.muted)
	var line string
	switch {
	case width >= 100:
		endpointWidth := maxInt(16, width-72)
		line = tableCell("STATUS", 9) + " " + tableCell("SANDBOX", 13) + " " + tableCell("HOST / DESTINATION", endpointWidth) + " " +
			tableCell("PROTO", 7) + " " + tableCell("↑ TX", 9) + " " + tableCell("↓ RX", 9) + " " + tableCell("PACKETS", 8) + " " + tableCell("LAST", 9)
	case width >= 86:
		endpointWidth := maxInt(16, width-61)
		line = tableCell("STATUS", 9) + " " + tableCell("SANDBOX", 13) + " " + tableCell("HOST / DESTINATION", endpointWidth) + " " +
			tableCell("PROTO", 7) + " " + tableCell("↑ TX", 9) + " " + tableCell("↓ RX", 9) + " " + tableCell("PACKETS", 8)
	case width >= 56:
		endpointWidth := maxInt(12, width-43)
		line = tableCell("", 2) + " " + tableCell("SANDBOX", 11) + " " + tableCell("HOST", endpointWidth) + " " +
			tableCell("↑ TX", 8) + " " + tableCell("↓ RX", 8)
	default:
		line = tableCell("", 2) + " " + tableCell("SANDBOX / HOST", maxInt(1, width-3))
	}
	return style.Render(truncateANSI(line, width))
}

func (m sandboxTUIModel) renderTrafficRow(theme tuiTheme, row tuiTrafficRow, width int) string {
	statusIcon := lipgloss.NewStyle().Foreground(theme.success).Render("✓")
	status := lipgloss.NewStyle().Foreground(theme.success).Render("ALLOW")
	if !row.Allowed {
		statusIcon = lipgloss.NewStyle().Foreground(theme.error).Render("×")
		status = lipgloss.NewStyle().Foreground(theme.error).Render("BLOCK")
	}
	endpoint := row.Host
	if endpoint == "" {
		endpoint = row.Address
	}
	if row.Port > 0 && row.Protocol != "dns" {
		endpoint += fmt.Sprintf(":%d", row.Port)
	}
	packets := row.TXPackets + row.RXPackets
	switch {
	case width >= 100:
		endpointWidth := maxInt(16, width-72)
		return tableCell(statusIcon+" "+status, 9) + " " + tableCell(row.Sandbox, 13) + " " + tableCell(endpoint, endpointWidth) + " " +
			tableCell(strings.ToUpper(row.Protocol), 7) + " " + tableCell(formatBytes(row.TXBytes), 9) + " " +
			tableCell(formatBytes(row.RXBytes), 9) + " " + tableCell(fmt.Sprint(packets), 8) + " " + tableCell(formatTrafficClock(row.LastSeen), 9)
	case width >= 86:
		endpointWidth := maxInt(16, width-61)
		return tableCell(statusIcon+" "+status, 9) + " " + tableCell(row.Sandbox, 13) + " " + tableCell(endpoint, endpointWidth) + " " +
			tableCell(strings.ToUpper(row.Protocol), 7) + " " + tableCell(formatBytes(row.TXBytes), 9) + " " +
			tableCell(formatBytes(row.RXBytes), 9) + " " + tableCell(fmt.Sprint(packets), 8)
	case width >= 56:
		endpointWidth := maxInt(12, width-43)
		return tableCell(statusIcon, 2) + " " + tableCell(row.Sandbox, 11) + " " + tableCell(endpoint, endpointWidth) + " " +
			tableCell(formatBytes(row.TXBytes), 8) + " " + tableCell(formatBytes(row.RXBytes), 8)
	default:
		label := row.Sandbox + "  " + endpoint + "  ↑" + formatBytes(row.TXBytes) + " ↓" + formatBytes(row.RXBytes)
		return tableCell(statusIcon, 2) + " " + tableCell(label, maxInt(1, width-3))
	}
}

func (m sandboxTUIModel) renderTrafficDetail(theme tuiTheme, width int) []string {
	if m.trafficCursor < 0 || m.trafficCursor >= len(m.traffic) || m.tableDetailHeight() == 0 {
		return nil
	}
	row := m.traffic[m.trafficCursor]
	endpoint := row.Address
	if row.Port > 0 {
		endpoint += fmt.Sprintf(":%d", row.Port)
	}
	decision := lipgloss.NewStyle().Foreground(theme.success).Render("allowed")
	if !row.Allowed {
		decision = lipgloss.NewStyle().Foreground(theme.error).Render("blocked by policy")
	}
	title := lipgloss.NewStyle().Bold(true).Foreground(theme.text).Render(row.Host)
	if row.Host == "" {
		title = lipgloss.NewStyle().Bold(true).Foreground(theme.text).Render(row.Address)
	}
	return []string{
		m.renderTableSeparator(theme, width),
		title + "  " + lipgloss.NewStyle().Foreground(theme.muted).Render(endpoint),
		lipgloss.NewStyle().Foreground(theme.secondary).Render(row.Sandbox+"  •  ") + decision + "  •  " + strings.ToUpper(row.Protocol),
		lipgloss.NewStyle().Foreground(theme.secondary).Render(fmt.Sprintf("↑ %s in %d packets   ↓ %s in %d packets", formatBytes(row.TXBytes), row.TXPackets, formatBytes(row.RXBytes), row.RXPackets)),
		lipgloss.NewStyle().Foreground(theme.muted).Render("first " + formatTrafficTime(row.FirstSeen) + "  •  last " + formatTrafficTime(row.LastSeen)),
	}
}

func (m sandboxTUIModel) renderRulesView(theme tuiTheme, layout tuiDashboardLayout) string {
	if m.loading {
		return m.renderTableLoading(theme, layout, "Loading network rules…")
	}
	if len(m.rules) == 0 {
		return m.renderTableEmpty(theme, layout, "No network rules", "Create a sandbox to see its effective egress policy.")
	}
	inner := maxInt(1, layout.width-4)
	lines := []string{m.renderRulesHeader(theme, inner), m.renderTableSeparator(theme, inner)}
	end := minInt(len(m.rules), m.rulesScroll+m.tableVisibleRows())
	for index := m.rulesScroll; index < end; index++ {
		line := m.renderRuleRow(theme, m.rules[index], inner)
		lines = append(lines, renderTableSelection(theme, line, inner, index == m.rulesCursor))
	}
	lines = m.appendTableDetail(lines, m.renderRuleDetail(theme, inner), layout.contentHeight)
	return renderTableSurface(theme, layout, lines)
}

func (m sandboxTUIModel) renderRulesHeader(theme tuiTheme, width int) string {
	style := lipgloss.NewStyle().Bold(true).Foreground(theme.muted)
	var line string
	if width >= 72 {
		targetWidth := maxInt(16, width-53)
		line = tableCell("ACTION", 9) + " " + tableCell("SANDBOX", 13) + " " + tableCell("TARGET", targetWidth) + " " +
			tableCell("PROTO", 8) + " " + tableCell("PORTS", 10)
	} else {
		targetWidth := maxInt(8, width-25)
		line = tableCell("", 2) + " " + tableCell("SANDBOX", 11) + " " + tableCell("TARGET", targetWidth) + " " + tableCell("PROTO", 8)
	}
	return style.Render(truncateANSI(line, width))
}

func (m sandboxTUIModel) renderRuleRow(theme tuiTheme, row tuiRuleRow, width int) string {
	icon, actionColor := "✓", theme.success
	switch row.Action {
	case "deny":
		icon, actionColor = "×", theme.error
	case "off":
		icon, actionColor = "○", theme.muted
	case "error":
		icon, actionColor = "!", theme.warning
	}
	action := lipgloss.NewStyle().Foreground(actionColor).Render(strings.ToUpper(row.Action))
	iconText := lipgloss.NewStyle().Foreground(actionColor).Render(icon)
	if width >= 72 {
		targetWidth := maxInt(16, width-53)
		return tableCell(iconText+" "+action, 9) + " " + tableCell(row.Sandbox, 13) + " " + tableCell(row.Target, targetWidth) + " " +
			tableCell(strings.ToUpper(row.Proto), 8) + " " + tableCell(defaultText(row.Ports, "—"), 10)
	}
	targetWidth := maxInt(8, width-25)
	return tableCell(iconText, 2) + " " + tableCell(row.Sandbox, 11) + " " + tableCell(row.Target, targetWidth) + " " + tableCell(strings.ToUpper(row.Proto), 8)
}

func (m sandboxTUIModel) renderRuleDetail(theme tuiTheme, width int) []string {
	if m.rulesCursor < 0 || m.rulesCursor >= len(m.rules) || m.tableDetailHeight() == 0 {
		return nil
	}
	row := m.rules[m.rulesCursor]
	actionColor := theme.success
	if row.Action == "deny" || row.Action == "error" {
		actionColor = theme.error
	}
	title := lipgloss.NewStyle().Bold(true).Foreground(actionColor).Render(strings.ToUpper(row.Action)) + "  " +
		lipgloss.NewStyle().Bold(true).Foreground(theme.text).Render(row.Target)
	return []string{
		m.renderTableSeparator(theme, width),
		title,
		lipgloss.NewStyle().Foreground(theme.secondary).Render(row.Sandbox + "  •  " + strings.ToUpper(row.Proto) + "  •  ports " + defaultText(row.Ports, "any")),
		lipgloss.NewStyle().Foreground(theme.muted).Render("source " + row.Source),
		lipgloss.NewStyle().Foreground(theme.muted).Render("policy " + defaultText(row.Policy, "built-in")),
	}
}

func (m sandboxTUIModel) renderPortsView(theme tuiTheme, layout tuiDashboardLayout) string {
	if m.loading {
		return m.renderTableLoading(theme, layout, "Loading published ports…")
	}
	if len(m.ports) == 0 {
		return m.renderTableEmpty(theme, layout, "No published ports", "Press p to publish a guest port on the host, or start with -p [IP:]HOST:GUEST[/udp].")
	}
	inner := maxInt(1, layout.width-4)
	lines := []string{m.renderPortsHeader(theme, inner), m.renderTableSeparator(theme, inner)}
	end := minInt(len(m.ports), m.portScroll+m.tableVisibleRows())
	for index := m.portScroll; index < end; index++ {
		line := m.renderPortRow(theme, m.ports[index], inner)
		lines = append(lines, renderTableSelection(theme, line, inner, index == m.portCursor))
	}
	lines = m.appendTableDetail(lines, m.renderPortDetail(theme, inner), layout.contentHeight)
	return renderTableSurface(theme, layout, lines)
}

func (m sandboxTUIModel) renderPortsHeader(theme tuiTheme, width int) string {
	style := lipgloss.NewStyle().Bold(true).Foreground(theme.muted)
	var line string
	if width >= 72 {
		bindWidth := maxInt(16, width-43)
		line = tableCell("STATE", 8) + " " + tableCell("SANDBOX", 14) + " " + tableCell("HOST BIND", bindWidth) + " " +
			tableCell("GUEST", 7) + " " + tableCell("PROTO", 5)
	} else {
		bindWidth := maxInt(12, width-27)
		line = tableCell("", 2) + " " + tableCell("SANDBOX", 12) + " " + tableCell("BIND", bindWidth) + " " + tableCell("GUEST", 6)
	}
	return style.Render(truncateANSI(line, width))
}

func (m sandboxTUIModel) renderPortRow(theme tuiTheme, row tuiPortRow, width int) string {
	icon, color := "\u21e2", theme.success
	state := row.State
	if state == "saved" {
		icon, color = "\u00b7", theme.info
	}
	if row.Error != "" {
		icon, color, state = "!", theme.error, "error"
	}
	stateText := lipgloss.NewStyle().Foreground(color).Render(strings.ToUpper(state))
	bind := row.Bind
	if row.Error != "" {
		bind = row.Error
	}
	guest := fmt.Sprintf("%d", row.Guest)
	if width >= 72 {
		bindWidth := maxInt(16, width-43)
		return tableCell(stateText, 8) + " " + tableCell(row.Sandbox, 14) + " " + tableCell(bind, bindWidth) + " " +
			tableCell(guest, 7) + " " + tableCell(row.Proto, 5)
	}
	bindWidth := maxInt(12, width-27)
	return tableCell(lipgloss.NewStyle().Foreground(color).Render(icon), 2) + " " + tableCell(row.Sandbox, 12) + " " +
		tableCell(bind, bindWidth) + " " + tableCell(guest, 6)
}

func (m sandboxTUIModel) renderPortDetail(theme tuiTheme, width int) []string {
	if m.portCursor < 0 || m.portCursor >= len(m.ports) || m.tableDetailHeight() == 0 {
		return nil
	}
	row := m.ports[m.portCursor]
	title := row.Sandbox + "  " + row.Bind + " \u2192 " + fmt.Sprintf("%d/%s", row.Guest, row.Proto)
	state := row.State
	if row.Error != "" {
		state = "error: " + row.Error
	}
	exposure := bindExposure(row.Bind)
	return []string{
		m.renderTableSeparator(theme, width),
		lipgloss.NewStyle().Bold(true).Foreground(theme.text).Render(title) + "  " + lipgloss.NewStyle().Foreground(theme.muted).Render(state),
		lipgloss.NewStyle().Foreground(theme.muted).Render("exposure   ") + lipgloss.NewStyle().Foreground(theme.secondary).Render(exposure),
		lipgloss.NewStyle().Foreground(theme.muted).Render("netpol     ") + lipgloss.NewStyle().Foreground(theme.secondary).Render("publishes are inbound holes: egress rules do not apply to forwarded connections"),
	}
}

// bindExposure classifies a bind address by parsing it, not by prefix
// matching: loopback stays loopback, wildcard is all-interfaces, and a
// specific LAN address is reported as such instead of mislabelled loopback.
func bindExposure(bind string) string {
	host, _, err := net.SplitHostPort(bind)
	if err != nil {
		return "unparseable bind"
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return "unparseable bind"
	}
	switch {
	case addr.IsLoopback():
		return "loopback only"
	case addr.IsUnspecified():
		return "all interfaces — LAN-reachable"
	default:
		return "host address " + host + " — reachable where that address routes"
	}
}

func (m sandboxTUIModel) renderMountsView(theme tuiTheme, layout tuiDashboardLayout) string {
	if m.loading {
		return m.renderTableLoading(theme, layout, "Loading mounts…")
	}
	if len(m.mounts) == 0 {
		return m.renderTableEmpty(theme, layout, "No host mounts", "Press a to attach a live share, or start with -share TAG=PATH[@CTRPATH][,ro].")
	}
	inner := maxInt(1, layout.width-4)
	lines := []string{m.renderMountsHeader(theme, inner), m.renderTableSeparator(theme, inner)}
	end := minInt(len(m.mounts), m.mountScroll+m.tableVisibleRows())
	for index := m.mountScroll; index < end; index++ {
		line := m.renderMountRow(theme, m.mounts[index], inner)
		lines = append(lines, renderTableSelection(theme, line, inner, index == m.mountCursor))
	}
	lines = m.appendTableDetail(lines, m.renderMountDetail(theme, inner), layout.contentHeight)
	return renderTableSurface(theme, layout, lines)
}

func (m sandboxTUIModel) renderMountsHeader(theme tuiTheme, width int) string {
	style := lipgloss.NewStyle().Bold(true).Foreground(theme.muted)
	var line string
	if width >= 72 {
		hostWidth := maxInt(14, (width-49)*3/5)
		guestWidth := maxInt(10, width-49-hostWidth)
		line = tableCell("MODE", 6) + " " + tableCell("STATE", 9) + " " + tableCell("SANDBOX", 12) + " " + tableCell("TAG", 10) + " " +
			tableCell("HOST PATH", hostWidth) + " " + tableCell("CONTAINER", guestWidth)
	} else {
		pathWidth := maxInt(8, width-27)
		line = tableCell("", 2) + " " + tableCell("SANDBOX", 11) + " " + tableCell("TAG", 10) + " " + tableCell("HOST PATH", pathWidth)
	}
	return style.Render(truncateANSI(line, width))
}

func (m sandboxTUIModel) renderMountRow(theme tuiTheme, row tuiMountRow, width int) string {
	icon, mode := "↔", "RW"
	color := theme.success
	if row.ReadOnly {
		icon, mode, color = "←", "RO", theme.info
	}
	if row.State == "restart" {
		icon, color = "↻", theme.warning
	}
	if row.Error != "" {
		icon, mode, color = "!", "ERR", theme.error
	}
	modeText := lipgloss.NewStyle().Foreground(color).Render(icon + " " + mode)
	state := row.State
	if state == "" {
		state = "active"
	}
	if row.Error != "" {
		state = "error"
	}
	stateText := lipgloss.NewStyle().Foreground(color).Render(strings.ToUpper(state))
	host := row.Host
	if row.Error != "" {
		host = row.Error
	}
	if width >= 72 {
		hostWidth := maxInt(14, (width-49)*3/5)
		guestWidth := maxInt(10, width-49-hostWidth)
		return tableCell(modeText, 6) + " " + tableCell(stateText, 9) + " " + tableCell(row.Sandbox, 12) + " " + tableCell(row.Tag, 10) + " " +
			tableCell(host, hostWidth) + " " + tableCell(row.Guest, guestWidth)
	}
	pathWidth := maxInt(8, width-27)
	return tableCell(lipgloss.NewStyle().Foreground(color).Render(icon), 2) + " " + tableCell(row.Sandbox, 11) + " " +
		tableCell(row.Tag, 10) + " " + tableCell(host, pathWidth)
}

func (m sandboxTUIModel) renderMountDetail(theme tuiTheme, width int) []string {
	if m.mountCursor < 0 || m.mountCursor >= len(m.mounts) || m.tableDetailHeight() == 0 {
		return nil
	}
	row := m.mounts[m.mountCursor]
	mode := "read-write"
	if row.ReadOnly {
		mode = "read-only"
	}
	state := row.State
	if state == "" {
		state = "active"
	}
	if row.Error != "" {
		mode = "invalid: " + row.Error
		state = "error"
	}
	return []string{
		m.renderTableSeparator(theme, width),
		lipgloss.NewStyle().Bold(true).Foreground(theme.text).Render(row.Sandbox+" / "+row.Tag) + "  " + lipgloss.NewStyle().Foreground(theme.info).Render(mode) + "  " + lipgloss.NewStyle().Foreground(theme.muted).Render(state),
		lipgloss.NewStyle().Foreground(theme.muted).Render("host       ") + lipgloss.NewStyle().Foreground(theme.secondary).Render(row.Host),
		lipgloss.NewStyle().Foreground(theme.muted).Render("VM         ") + lipgloss.NewStyle().Foreground(theme.secondary).Render(row.VM),
		lipgloss.NewStyle().Foreground(theme.muted).Render("container  ") + lipgloss.NewStyle().Foreground(theme.secondary).Render(row.Guest),
	}
}

func (m sandboxTUIModel) appendTableDetail(lines, detail []string, height int) []string {
	if len(detail) == 0 {
		return lines
	}
	for len(lines)+len(detail) < height {
		lines = append(lines, "")
	}
	return append(lines, detail...)
}

func (m sandboxTUIModel) renderTableLoading(theme tuiTheme, layout tuiDashboardLayout, label string) string {
	content := m.spinner.View() + " " + lipgloss.NewStyle().Foreground(theme.secondary).Render(label)
	style := lipgloss.NewStyle().Foreground(theme.text).Background(theme.bg).
		Width(layout.width).Height(layout.contentHeight).Align(lipgloss.Center, lipgloss.Center)
	return renderSurface(style, theme.text, theme.bg, content)
}

func (m sandboxTUIModel) renderTableEmpty(theme tuiTheme, layout tuiDashboardLayout, title, description string) string {
	inner := maxInt(12, layout.width-8)
	content := lipgloss.NewStyle().Bold(true).Foreground(theme.text).Render(title) + "\n" +
		lipgloss.NewStyle().Foreground(theme.muted).Render(truncateText(description, inner))
	style := lipgloss.NewStyle().Foreground(theme.text).Background(theme.bg).
		Width(layout.width).Height(layout.contentHeight).Align(lipgloss.Center, lipgloss.Center)
	return renderSurface(style, theme.text, theme.bg, content)
}

func renderTableSurface(theme tuiTheme, layout tuiDashboardLayout, lines []string) string {
	inner := maxInt(1, layout.width-4)
	for index := range lines {
		lines[index] = truncateANSI(lines[index], inner)
	}
	content := padLeftBlock(strings.Join(lines, "\n"), 2)
	style := lipgloss.NewStyle().Foreground(theme.text).Background(theme.bg).
		Width(layout.width).Height(layout.contentHeight).MaxHeight(layout.contentHeight)
	return renderSurface(style, theme.text, theme.bg, content)
}

func renderTableSelection(theme tuiTheme, line string, width int, selected bool) string {
	background := theme.bg
	if selected {
		background = theme.panelSelected
	}
	style := lipgloss.NewStyle().Foreground(theme.secondary).Background(background).Width(width)
	return renderSurface(style, theme.secondary, background, truncateANSI(line, width))
}

func (m sandboxTUIModel) renderTableSeparator(theme tuiTheme, width int) string {
	return lipgloss.NewStyle().Foreground(theme.borderMuted).Render(strings.Repeat("─", maxInt(1, width)))
}

func (m sandboxTUIModel) renderActiveScrollbar(theme tuiTheme, layout tuiDashboardLayout) string {
	if m.page == tuiSandboxesPage {
		return m.renderCardScrollbar(theme, layout)
	}
	_, scroll, count := m.tableState()
	visible := m.tableVisibleRows()
	if scroll == nil || count <= visible || layout.contentHeight < 2 {
		return ""
	}
	trackHeight := layout.contentHeight
	thumbHeight := maxInt(1, trackHeight*visible/count)
	thumbTop := (trackHeight - thumbHeight) * *scroll / maxInt(1, count-visible)
	lines := make([]string, trackHeight)
	for index := range lines {
		glyph, color := "│", theme.borderMuted
		if index >= thumbTop && index < thumbTop+thumbHeight {
			glyph, color = "┃", theme.accent
		}
		lines[index] = lipgloss.NewStyle().Foreground(color).Background(theme.bg).Render(glyph)
	}
	return strings.Join(lines, "\n")
}

func tableCell(value string, width int) string {
	value = truncateANSI(value, maxInt(1, width))
	return value + strings.Repeat(" ", maxInt(0, width-lipgloss.Width(value)))
}

func defaultText(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func formatBytes(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%dB", bytes)
	}
	value := float64(bytes)
	units := []string{"K", "M", "G", "T"}
	for _, suffix := range units {
		value /= unit
		if value < unit {
			if value < 10 {
				return fmt.Sprintf("%.1f%s", value, suffix)
			}
			return fmt.Sprintf("%.0f%s", value, suffix)
		}
	}
	return fmt.Sprintf("%.0fP", value/unit)
}

func formatTrafficClock(value time.Time) string {
	if value.IsZero() {
		return "—"
	}
	local := value.Local()
	if time.Since(value) < 24*time.Hour {
		return local.Format("15:04:05")
	}
	return local.Format("Jan02 15")
}

func formatTrafficTime(value time.Time) string {
	if value.IsZero() {
		return "unknown"
	}
	if time.Since(value) < 24*time.Hour {
		return value.Local().Format("15:04:05")
	}
	return value.Local().Format("Jan 02 15:04")
}
