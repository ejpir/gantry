package dashboard

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"charm.land/lipgloss/v2"
)

type overviewDeniedGroup struct {
	label string
	at    time.Time
}

// Group only the overview's presentation. The traffic table keeps every flow,
// including protocols, addresses, timestamps, and packet counters.
func (m sandboxTUIModel) overviewDeniedGroups(sandbox string) []overviewDeniedGroup {
	byHost := make(map[string]time.Time)
	for _, row := range m.traffic {
		if row.Sandbox != sandbox || row.Allowed {
			continue
		}
		host := defaultText(row.Host, row.Address)
		if host == "" {
			continue
		}
		if address, err := netip.ParseAddr(host); err == nil {
			host = address.String()
		}
		if latest, found := byHost[host]; !found || row.LastSeen.After(latest) {
			byHost[host] = row.LastSeen
		}
	}
	groups := make([]overviewDeniedGroup, 0, len(byHost))
	multicastTargets := 0
	var multicastLatest time.Time
	for host, at := range byHost {
		address, err := netip.ParseAddr(host)
		if err == nil && address.Is6() && !address.Is4In6() && address.IsMulticast() {
			multicastTargets++
			if at.After(multicastLatest) {
				multicastLatest = at
			}
			continue
		}
		groups = append(groups, overviewDeniedGroup{label: host, at: at})
	}
	if multicastTargets > 0 {
		groups = append(groups, overviewDeniedGroup{
			label: "IPv6 multicast ×" + pluralCount(multicastTargets, "target"),
			at:    multicastLatest,
		})
	}
	sort.Slice(groups, func(i, j int) bool {
		if groups[i].at.Equal(groups[j].at) {
			return groups[i].label < groups[j].label
		}
		return groups[i].at.After(groups[j].at)
	})
	return groups
}

func (m sandboxTUIModel) recentDeniedHosts(theme tuiTheme, sandbox string, limit int) string {
	if limit <= 0 {
		return ""
	}
	groups := m.overviewDeniedGroups(sandbox)
	muted := lipgloss.NewStyle().Foreground(theme.muted)
	if len(groups) == 0 {
		return muted.Render("none recorded")
	}
	values := make([]string, 0, minInt(len(groups), limit)+1)
	for _, group := range groups[:minInt(len(groups), limit)] {
		values = append(values, lipgloss.NewStyle().Foreground(theme.secondary).Render(group.label))
	}
	if len(groups) > limit {
		values = append(values, muted.Render(fmt.Sprintf("+%d more", len(groups)-limit)))
	}
	return strings.Join(values, muted.Render(" · "))
}

// Return actions from the same rows used to draw them, so resize, selection,
// and variable mount/port counts cannot leave stale mouse targets behind.
func (m sandboxTUIModel) renderOverviewInspector(theme tuiTheme, rect tuiRect) (string, []tuiHitTarget) {
	selected := m.selected()
	if selected == nil || rect.w == 0 || rect.h < 8 {
		return "", nil
	}
	inner := maxInt(1, rect.w-4)
	muted := lipgloss.NewStyle().Foreground(theme.muted)
	secondary := lipgloss.NewStyle().Foreground(theme.secondary)
	accent := lipgloss.NewStyle().Bold(true).Foreground(theme.accent)
	section := func(title string, rows []string) []string {
		return append([]string{muted.Render(title)}, rows...)
	}
	lines := []string{
		muted.Render("SELECTED / ") + accent.Render(selected.Name),
		muted.Render(strings.Repeat("─", inner)),
		"",
	}
	if selected.ConfigError {
		lines = append(lines, lipgloss.NewStyle().Foreground(theme.warning).Render("Configuration unavailable"), "")
	}

	mounts := m.overviewInspectorMounts(theme, *selected)
	lines = append(lines, section("MOUNTS", mounts)...)
	lines = append(lines, "")
	networkTitle := "NETWORK"
	if selected.State != tuiRunning {
		networkTitle += " / saved"
	}
	lines = append(lines, section(networkTitle, m.overviewInspectorNetwork(theme, *selected))...)
	lines = append(lines, "")
	groups := m.overviewDeniedGroups(selected.Name)
	denied := []string{muted.Render("none recorded")}
	if len(groups) > 0 {
		denied = nil
		for _, group := range groups[:minInt(2, len(groups))] {
			denied = append(denied, secondary.Render(group.label))
		}
		if len(groups) > 2 {
			denied = append(denied, muted.Render(fmt.Sprintf("+%d more · t opens traffic", len(groups)-2)))
		} else if at := m.lastDeniedAt(selected.Name); !at.IsZero() {
			denied = append(denied, muted.Render("last "+formatOverviewDenyClock(at)))
		}
	}
	lines = append(lines, section("RECENT BLOCKS", denied)...)

	actions := []struct{ key, label string }{
		{"enter", "Open sandbox"},
		{"t", "View traffic"},
		{"e", "Edit configuration"},
		{"i", "Full sandbox details"},
	}
	if m.busyAction != "" {
		actions = nil
	}
	bodyHeight := rect.h - 2
	actionStart := bodyHeight - len(actions) - 2 // blank row and section heading
	if len(lines) > actionStart {
		lines = lines[:actionStart]
	}
	for len(lines) < actionStart {
		lines = append(lines, "")
	}
	lines = append(lines, "", muted.Render("ACTIONS"))
	var targets []tuiHitTarget
	for _, action := range actions {
		text := accent.Width(6).Render(action.key) + secondary.Render(action.label)
		text = truncateANSI(text, inner)
		targets = append(targets, tuiHitTarget{
			kind: "shortcut", action: action.key,
			rect: tuiRect{x: rect.x + 2, y: rect.y + 1 + len(lines), w: lipgloss.Width(text), h: 1},
		})
		lines = append(lines, text)
	}
	if m.busyAction != "" {
		// Replace the action heading rather than advertising disabled controls.
		lines[len(lines)-1] = muted.Render("Action in progress…")
	}
	for i := range lines {
		lines[i] = truncateANSI(lines[i], inner)
	}
	style := lipgloss.NewStyle().Foreground(theme.text).Background(theme.panel).
		Border(lipgloss.RoundedBorder()).BorderForeground(theme.border).
		Padding(0, 1).Width(rect.w).Height(rect.h).MaxHeight(rect.h)
	return renderSurface(style, theme.text, theme.panel, strings.Join(lines, "\n")), targets
}

func (m sandboxTUIModel) overviewInspectorMounts(theme tuiTheme, selected tuiSandbox) []string {
	var rows []string
	for _, mount := range m.mounts {
		if mount.Sandbox != selected.Name {
			continue
		}
		if mount.Error != "" {
			rows = append(rows, lipgloss.NewStyle().Foreground(theme.error).Render("! "+safeUILine(mount.Error)))
			continue
		}
		mode, color := "rw", theme.warning
		if mount.ReadOnly {
			mode, color = "ro", theme.muted
		}
		path := defaultText(mount.Guest, defaultText(mount.VM, mount.Tag))
		rows = append(rows, lipgloss.NewStyle().Foreground(color).Render(mode+"  ")+
			lipgloss.NewStyle().Foreground(theme.secondary).Render(safeUILine(path)))
	}
	muted := lipgloss.NewStyle().Foreground(theme.muted)
	if len(rows) == 0 {
		if selected.Shares > 0 || selected.ConfigError {
			return []string{muted.Render("details unavailable")}
		}
		return []string{muted.Render("none configured")}
	}
	if len(rows) > 3 {
		rows = append(rows[:2], muted.Render(fmt.Sprintf("+%d more · see Mounts", len(rows)-2)))
	}
	return rows
}

func (m sandboxTUIModel) overviewInspectorNetwork(theme tuiTheme, selected tuiSandbox) []string {
	muted := lipgloss.NewStyle().Foreground(theme.muted)
	secondary := lipgloss.NewStyle().Foreground(theme.secondary)
	if selected.ConfigError {
		return []string{muted.Render("configuration unavailable")}
	}
	policy := "built-in"
	if selected.NetPolicy != "" {
		policy = filepath.Base(selected.NetPolicy)
	}
	rows := []string{muted.Render("Policy  ") + secondary.Render(safeUILine(policy))}
	if !selected.Net {
		rows[0] = muted.Render("Network disabled")
	}
	var ports []string
	for _, port := range m.ports {
		if port.Sandbox != selected.Name {
			continue
		}
		endpoint := fmt.Sprintf("%s → %d/%s", port.Bind, port.Guest, defaultText(port.Proto, "tcp"))
		color := theme.secondary
		if port.Error != "" || port.State == "error" {
			endpoint, color = "! "+endpoint+" (error)", theme.error
		} else if port.State != "bound" || selected.State != tuiRunning {
			state := defaultText(port.State, "saved")
			if state == "bound" {
				state = "saved"
			}
			endpoint = "○ " + endpoint + " (" + state + ")"
		}
		ports = append(ports, lipgloss.NewStyle().Foreground(color).Render(safeUILine(endpoint)))
	}
	switch {
	case len(ports) == 0 && selected.Ports > 0:
		rows = append(rows, muted.Render("port details unavailable"))
	case len(ports) == 0:
		rows = append(rows, muted.Render("no published ports"))
	case len(ports) > 2:
		rows = append(rows, ports[0], muted.Render(fmt.Sprintf("+%d more · see Ports", len(ports)-1)))
	default:
		rows = append(rows, ports...)
	}
	return rows
}
