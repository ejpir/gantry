package dashboard

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"charm.land/lipgloss/v2"
)

const tuiTableHeaderHeight = 2

func (m sandboxTUIModel) pageRowCount(page tuiPage) int {
	switch page {
	case tuiOverviewPage:
		return len(m.sandboxes)
	case tuiTrafficPage:
		return len(m.traffic)
	case tuiRulesPage:
		return len(m.rules)
	case tuiMountsPage:
		return len(m.mounts)
	case tuiPortsPage:
		return len(m.ports)
	case tuiSecretsPage:
		return len(m.secrets)
	case tuiMCPPage:
		return len(m.mcpServers)
	case tuiPacketsPage:
		return len(m.packets)
	case tuiImagesPage:
		if m.imageSection == tuiImageSectionCredentials {
			return len(m.registries)
		}
		return len(m.images)
	default:
		return len(m.sandboxes)
	}
}

func (m sandboxTUIModel) tableDetailHeight() int {
	if m.page == tuiPacketsPage && m.dashboardLayout().contentHeight >= 14 {
		return 6
	}
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
	return m.renderPopulatedTable(theme, layout, tuiTrafficPage)
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
	return m.renderStandardTable(theme, layout, tuiRulesPage, "Loading network rules…", "No network rules", "Create a sandbox to see its effective egress policy.")
}

func (m sandboxTUIModel) renderSecretsView(theme tuiTheme, layout tuiDashboardLayout) string {
	return m.renderStandardTable(theme, layout, tuiSecretsPage, "Loading secret names…", "No secrets configured", "Press a to load a memory-only secret into a running sandbox.")
}

func (m sandboxTUIModel) renderSecretsHeader(theme tuiTheme, width int) string {
	style := lipgloss.NewStyle().Bold(true).Foreground(theme.muted)
	nameWidth := maxInt(12, width-30)
	line := tableCell("SANDBOX", 13) + " " + tableCell("NAME", nameWidth) + " " + tableCell("STATE", 15)
	return style.Render(truncateANSI(line, width))
}

func (m sandboxTUIModel) renderSecretRow(theme tuiTheme, row tuiSecretRow, width int) string {
	stateColor := theme.warning
	icon := "○"
	if row.State == "loaded" {
		stateColor = theme.success
		icon = "✓"
	}
	nameWidth := maxInt(12, width-30)
	state := lipgloss.NewStyle().Foreground(stateColor).Render(icon + " " + row.State)
	return tableCell(row.Sandbox, 13) + " " + tableCell(row.Name, nameWidth) + " " + tableCell(state, 15)
}

func (m sandboxTUIModel) renderSecretDetail(theme tuiTheme, width int) []string {
	if m.secretCursor < 0 || m.secretCursor >= len(m.secrets) || m.tableDetailHeight() == 0 {
		return nil
	}
	row := m.secrets[m.secretCursor]
	return []string{
		m.renderTableSeparator(theme, width),
		lipgloss.NewStyle().Bold(true).Foreground(theme.text).Render(row.Name),
		lipgloss.NewStyle().Foreground(theme.secondary).Render(row.Sandbox + "  •  " + row.State),
		lipgloss.NewStyle().Foreground(theme.muted).Render("Values are write-only, memory-only, and never shown in this table."),
		lipgloss.NewStyle().Foreground(theme.muted).Render("Export this name before restarting the sandbox."),
	}
}

func (m sandboxTUIModel) renderMCPView(theme tuiTheme, layout tuiDashboardLayout) string {
	return m.renderStandardTable(theme, layout, tuiMCPPage, "Loading MCP servers…", "No MCP servers configured", "Press f to configure the built-in filesystem server or a to add a remote server.")
}

func (m sandboxTUIModel) renderMCPHeader(theme tuiTheme, width int) string {
	style := lipgloss.NewStyle().Bold(true).Foreground(theme.muted)
	var line string
	if width >= 82 {
		endpointWidth := maxInt(18, width-54)
		line = tableCell("STATE", 9) + " " + tableCell("SANDBOX", 13) + " " + tableCell("SERVER", 12) + " " +
			tableCell("TYPE", 7) + " " + tableCell("ENDPOINT / ROOT", endpointWidth) + " " + tableCell("AUTH", 9)
	} else {
		endpointWidth := maxInt(12, width-32)
		line = tableCell("", 2) + " " + tableCell("SANDBOX", 11) + " " + tableCell("SERVER", 10) + " " + tableCell("ENDPOINT", endpointWidth)
	}
	return style.Render(truncateANSI(line, width))
}

func (m sandboxTUIModel) renderMCPRow(theme tuiTheme, row tuiMCPRow, width int) string {
	icon, stateColor := "✓", theme.success
	switch row.State {
	case "saved":
		icon, stateColor = "·", theme.info
	case "restart":
		icon, stateColor = "↻", theme.warning
	}
	if row.Error != "" {
		icon, stateColor = "!", theme.error
	}
	endpoint := row.URL
	if row.Type == "local" {
		endpoint = row.Root
	}
	if row.Error != "" {
		endpoint = row.Error
	}
	auth := defaultText(row.AuthKind, "none")
	state := strings.ToUpper(row.State)
	if row.Error != "" {
		state = "ERROR"
	}
	if width >= 82 {
		endpointWidth := maxInt(18, width-54)
		return tableCell(lipgloss.NewStyle().Foreground(stateColor).Render(icon+" "+state), 9) + " " +
			tableCell(row.Sandbox, 13) + " " + tableCell(row.Name, 12) + " " + tableCell(strings.ToUpper(row.Type), 7) + " " +
			tableCell(endpoint, endpointWidth) + " " + tableCell(auth, 9)
	}
	endpointWidth := maxInt(12, width-32)
	return tableCell(lipgloss.NewStyle().Foreground(stateColor).Render(icon), 2) + " " + tableCell(row.Sandbox, 11) + " " +
		tableCell(row.Name, 10) + " " + tableCell(endpoint, endpointWidth)
}

func (m sandboxTUIModel) renderMCPDetail(theme tuiTheme, width int) []string {
	if m.mcpCursor < 0 || m.mcpCursor >= len(m.mcpServers) || m.tableDetailHeight() == 0 {
		return nil
	}
	row := m.mcpServers[m.mcpCursor]
	title := lipgloss.NewStyle().Bold(true).Foreground(theme.text).Render(row.Sandbox + " / " + row.Name)
	if row.Error != "" {
		return []string{m.renderTableSeparator(theme, width), title, lipgloss.NewStyle().Foreground(theme.error).Render(row.Error), "", ""}
	}
	if row.Type == "local" {
		return []string{
			m.renderTableSeparator(theme, width), title + "  " + lipgloss.NewStyle().Foreground(theme.info).Render("built-in read-only filesystem"),
			lipgloss.NewStyle().Foreground(theme.muted).Render("root       ") + lipgloss.NewStyle().Foreground(theme.secondary).Render(row.Root),
			lipgloss.NewStyle().Foreground(theme.muted).Render("guest user ") + lipgloss.NewStyle().Foreground(theme.secondary).Render(row.User),
			lipgloss.NewStyle().Foreground(theme.muted).Render("tools      read_file, list_directory  •  ") + row.State,
		}
	}
	auth := "none"
	if row.AuthKind != "" {
		auth = row.AuthKind + ":" + row.AuthRef
		if row.AuthKind == "header" {
			auth = "header " + row.AuthHeader + ":" + row.AuthRef
		}
	}
	policy := "allow " + defaultText(strings.Join(row.Allow, ", "), "none") + "  •  deny " + defaultText(strings.Join(row.Deny, ", "), "none")
	redact := defaultText(strings.Join(row.Redact, ", "), "none")
	return []string{
		m.renderTableSeparator(theme, width), title + "  " + lipgloss.NewStyle().Foreground(theme.secondary).Render(row.URL),
		lipgloss.NewStyle().Foreground(theme.muted).Render("auth       ") + lipgloss.NewStyle().Foreground(theme.secondary).Render(auth),
		lipgloss.NewStyle().Foreground(theme.muted).Render("policy     ") + lipgloss.NewStyle().Foreground(theme.secondary).Render(policy),
		lipgloss.NewStyle().Foreground(theme.muted).Render("redact     ") + lipgloss.NewStyle().Foreground(theme.secondary).Render(redact+"  •  "+row.State),
	}
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
	return m.renderStandardTable(theme, layout, tuiPortsPage, "Loading published ports…", "No published ports", "Press p to publish a guest port on the host, or start with -p [IP:]HOST:GUEST[/udp].")
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
	return m.renderStandardTable(theme, layout, tuiMountsPage, "Loading mounts…", "No host mounts", "Press a to add a share now or save one for the next start.")
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

func (m sandboxTUIModel) renderStandardTable(theme tuiTheme, layout tuiDashboardLayout, page tuiPage, loading, emptyTitle, emptyDescription string) string {
	if m.loading {
		return m.renderTableLoading(theme, layout, loading)
	}
	if m.pageRowCount(page) == 0 {
		return m.renderTableEmpty(theme, layout, emptyTitle, emptyDescription)
	}
	return m.renderPopulatedTable(theme, layout, page)
}

func (m sandboxTUIModel) renderPopulatedTable(theme tuiTheme, layout tuiDashboardLayout, page tuiPage) string {
	inner := maxInt(1, layout.width-4)
	scroll, cursor := m.tableRenderPosition(page)
	count := m.pageRowCount(page)
	scroll = clampInt(scroll, 0, count)
	end := minInt(count, scroll+m.tableVisibleRows())
	capacity := maxInt(layout.contentHeight, 2+(end-scroll)+m.tableDetailHeight())
	lines := make([]string, 0, capacity)
	lines = append(lines, m.renderTableHeader(theme, page, inner), m.renderTableSeparator(theme, inner))
	for index := scroll; index < end; index++ {
		line := m.renderTableRow(theme, page, index, inner)
		lines = append(lines, renderTableSelection(theme, line, inner, index == cursor))
	}
	lines = m.appendTableDetail(lines, m.renderTableDetail(theme, page, inner), layout.contentHeight)
	return renderTableSurface(theme, layout, lines)
}

func (m sandboxTUIModel) tableRenderPosition(page tuiPage) (scroll, cursor int) {
	switch page {
	case tuiTrafficPage:
		return m.trafficScroll, m.trafficCursor
	case tuiRulesPage:
		return m.rulesScroll, m.rulesCursor
	case tuiMountsPage:
		return m.mountScroll, m.mountCursor
	case tuiPortsPage:
		return m.portScroll, m.portCursor
	case tuiSecretsPage:
		return m.secretScroll, m.secretCursor
	case tuiMCPPage:
		return m.mcpScroll, m.mcpCursor
	case tuiPacketsPage:
		return m.packetScroll, m.packetCursor
	case tuiImagesPage:
		if m.imageSection == tuiImageSectionCredentials {
			return m.registryScroll, m.registryCursor
		}
		return m.imageScroll, m.imageCursor
	default:
		return 0, 0
	}
}

func (m sandboxTUIModel) renderTableHeader(theme tuiTheme, page tuiPage, width int) string {
	switch page {
	case tuiTrafficPage:
		return m.renderTrafficHeader(theme, width)
	case tuiRulesPage:
		return m.renderRulesHeader(theme, width)
	case tuiMountsPage:
		return m.renderMountsHeader(theme, width)
	case tuiPortsPage:
		return m.renderPortsHeader(theme, width)
	case tuiSecretsPage:
		return m.renderSecretsHeader(theme, width)
	case tuiMCPPage:
		return m.renderMCPHeader(theme, width)
	case tuiPacketsPage:
		return m.renderPacketsHeader(theme, width)
	case tuiImagesPage:
		if m.imageSection == tuiImageSectionCredentials {
			return m.renderRegistriesHeader(theme, width)
		}
		return m.renderImagesHeader(theme, width)
	default:
		return ""
	}
}

func (m sandboxTUIModel) renderTableRow(theme tuiTheme, page tuiPage, index, width int) string {
	switch page {
	case tuiTrafficPage:
		return m.renderTrafficRow(theme, m.traffic[index], width)
	case tuiRulesPage:
		return m.renderRuleRow(theme, m.rules[index], width)
	case tuiMountsPage:
		return m.renderMountRow(theme, m.mounts[index], width)
	case tuiPortsPage:
		return m.renderPortRow(theme, m.ports[index], width)
	case tuiSecretsPage:
		return m.renderSecretRow(theme, m.secrets[index], width)
	case tuiMCPPage:
		return m.renderMCPRow(theme, m.mcpServers[index], width)
	case tuiPacketsPage:
		return m.renderPacketRow(theme, m.packets[index], width)
	case tuiImagesPage:
		if m.imageSection == tuiImageSectionCredentials {
			return m.renderRegistryRow(theme, m.registries[index], width)
		}
		return m.renderImageRow(theme, m.images[index], width)
	default:
		return ""
	}
}

func (m sandboxTUIModel) renderTableDetail(theme tuiTheme, page tuiPage, width int) []string {
	switch page {
	case tuiTrafficPage:
		return m.renderTrafficDetail(theme, width)
	case tuiRulesPage:
		return m.renderRuleDetail(theme, width)
	case tuiMountsPage:
		return m.renderMountDetail(theme, width)
	case tuiPortsPage:
		return m.renderPortDetail(theme, width)
	case tuiSecretsPage:
		return m.renderSecretDetail(theme, width)
	case tuiMCPPage:
		return m.renderMCPDetail(theme, width)
	case tuiPacketsPage:
		return m.renderPacketDetail(theme, width)
	case tuiImagesPage:
		if m.imageSection == tuiImageSectionCredentials {
			return m.renderRegistryDetail(theme, width)
		}
		return m.renderImageDetail(theme, width)
	default:
		return nil
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
	if m.page == tuiOverviewPage {
		return renderListScrollbar(theme, layout.contentHeight, len(m.sandboxes), m.overviewNavigationCapacity(layout), m.scrollRow)
	}
	if m.page == tuiSandboxesPage {
		if m.usesMasterDetail(layout) {
			return renderListScrollbar(theme, layout.contentHeight, m.entryCount(), m.masterVisibleItems(layout), m.scrollRow)
		}
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
