package dashboard

import (
	"fmt"
	"path"
	"runtime"
	"strings"

	"charm.land/lipgloss/v2"
)

const (
	tuiStackMaxWidth  = 118
	tuiStackMinHeight = 23
	// Ordinary monospace characters, not emoji, private-use glyphs, or images.
	// All icons occupy three rows and at most six terminal cells per row.
	tuiStackCube = "  ___ \n /__/|\n |__|/"
	tuiStackChip = " ┌┬┬┐ \n─┤□ ├─\n └┴┴┘ "
)

type tuiStackMode int

const (
	tuiStackCompact tuiStackMode = iota
	tuiStackIcons
	tuiStackFull
)

var tuiStackBoundary = lipgloss.Border{
	Top: "╌", Bottom: "╌", Left: "╎", Right: "╎",
	TopLeft: "╭", TopRight: "╮", BottomLeft: "╰", BottomRight: "╯",
}

// Local paths get a basename in the diagram; OCI registry/repository identity
// is retained. Details still receives the original, unmodified configuration.
func stackImageLabel(ref string) string {
	ref = safeUILine(ref)
	normalized := strings.ReplaceAll(ref, "\\", "/")
	if path.IsAbs(normalized) || strings.HasPrefix(normalized, "file://") ||
		(len(normalized) >= 3 && normalized[1] == ':' && normalized[2] == '/') {
		return path.Base(normalized)
	}
	return shortImageRef(ref)
}

func stackHostBackend(goos string) (string, string) {
	switch goos {
	case "linux":
		return "KVM", "Linux"
	case "darwin":
		return "Hypervisor.framework", "macOS"
	case "windows":
		return "WHPX", "Windows"
	default:
		return "Platform hypervisor", goos
	}
}

func renderStackIconLabel(theme tuiTheme, icon, title, subtitle string, width int, accent bool) string {
	color := theme.secondary
	if accent {
		color = theme.accent
	}
	textWidth := maxInt(1, width-8)
	text := "\n" + lipgloss.NewStyle().Bold(true).Foreground(color).Render(truncateText(title, textWidth)) + "\n" +
		lipgloss.NewStyle().Foreground(theme.muted).Render(truncateText(subtitle, textWidth))
	return lipgloss.JoinHorizontal(lipgloss.Top, lipgloss.NewStyle().Foreground(color).Width(6).Render(icon), "  ", text)
}

func renderStackNode(theme tuiTheme, width int, title string, rows []string) string {
	inner := maxInt(1, width-4)
	lines := []string{lipgloss.NewStyle().Bold(true).Foreground(theme.text).Render(truncateText(title, inner)), ""}
	for _, row := range rows {
		lines = append(lines, truncateANSI(row, inner))
	}
	style := lipgloss.NewStyle().Foreground(theme.secondary).Background(theme.panelRaised).
		Border(lipgloss.RoundedBorder()).BorderForeground(theme.borderMuted).Padding(0, 1).Width(width).Align(lipgloss.Center)
	return renderSurface(style, theme.secondary, theme.panelRaised, strings.Join(lines, "\n"))
}

func renderStackStage(theme tuiTheme, width int, icon, title, subtitle string, rich bool) string {
	inner := maxInt(1, width-6)
	body := lipgloss.NewStyle().Foreground(theme.secondary).Render(truncateText(title, inner))
	if rich {
		body = renderStackIconLabel(theme, icon, title, subtitle, inner, false)
	}
	style := lipgloss.NewStyle().Foreground(theme.secondary).Background(theme.panel).
		Border(lipgloss.RoundedBorder()).BorderForeground(theme.borderMuted).Padding(0, 2).Width(width).Align(lipgloss.Center)
	return renderSurface(style, theme.secondary, theme.panel, body)
}

func (m sandboxTUIModel) stackActions(theme tuiTheme, selected tuiSandbox, width, y int) (string, []tuiHitTarget) {
	if m.busyAction != "" {
		return lipgloss.NewStyle().Foreground(theme.muted).Render("Action in progress…"), nil
	}
	actions := [][2]string{}
	if selected.State != tuiStarting && !selected.ConfigError {
		label := "Start"
		if selected.State == tuiRunning {
			label = "Open"
		}
		actions = append(actions, [2]string{"enter", label})
		if selected.State == tuiRunning {
			actions = append(actions, [2]string{"s", "Stop"})
		}
	}
	actions = append(actions, [2]string{"e", "Edit"}, [2]string{"i", "Details"})
	var parts []string
	var hits []tuiHitTarget
	x := 0
	for _, action := range actions {
		style := lipgloss.NewStyle().Foreground(theme.secondary).Background(theme.panel).Padding(0, 1)
		if action[0] == "enter" {
			style = style.Foreground(theme.accentFg).Background(theme.accent).Bold(true)
		}
		label := style.Render(action[0] + " " + action[1])
		w := lipgloss.Width(label)
		if x+w > width {
			break
		}
		parts = append(parts, label)
		hits = append(hits, tuiHitTarget{kind: "shortcut", action: action[0], rect: tuiRect{x: x, y: y, w: w, h: 1}})
		x += w + 2
	}
	return strings.Join(parts, "  "), hits
}

// Both drawing and hit-testing use this builder. Targets are relative to the
// detail component, including the measured workload node and header actions.
func (m sandboxTUIModel) renderSandboxStack(theme tuiTheme, width, height int) (string, []tuiHitTarget) {
	selected := m.selected()
	if selected == nil {
		content := renderStackIconLabel(theme, tuiStackCube, "Create a sandbox", "Choose an OCI image and resources.", maxInt(1, width-4), true) + "\n\n" +
			lipgloss.NewStyle().Foreground(theme.secondary).Render(truncateText("Press enter or n to continue.", maxInt(1, width-4)))
		style := lipgloss.NewStyle().Foreground(theme.text).Background(theme.panel).
			Border(tuiStackBoundary).BorderForeground(theme.border).Padding(1, 1).Width(width)
		body := renderSurface(style, theme.text, theme.panel, content)
		hits := []tuiHitTarget{{kind: "create", index: m.cursor, rect: tuiRect{w: width, h: lipgloss.Height(body)}}}
		return renderSurface(lipgloss.NewStyle().Width(width).Height(height), theme.text, theme.bg, body), hits
	}
	var content string
	var hits []tuiHitTarget
	for _, mode := range []tuiStackMode{tuiStackFull, tuiStackIcons, tuiStackCompact} {
		content, hits = m.buildSandboxStack(theme, *selected, width, mode)
		if lipgloss.Height(content) <= height {
			break
		}
	}
	// Keep targets within the actual visible component even on tiny viewports.
	var visible []tuiHitTarget
	if m.busyAction == "" {
		for _, hit := range hits {
			if rect, ok := intersectRect(hit.rect, tuiRect{w: width, h: height}); ok {
				hit.rect = rect
				visible = append(visible, hit)
			}
		}
	}
	style := lipgloss.NewStyle().Foreground(theme.text).Background(theme.bg).Width(width).Height(height).MaxHeight(height)
	return renderSurface(style, theme.text, theme.bg, sliceBlockLines(content, 0, height)), visible
}

func (m sandboxTUIModel) buildSandboxStack(theme tuiTheme, selected tuiSandbox, width int, mode tuiStackMode) (string, []tuiHitTarget) {
	rich, icons := mode == tuiStackFull, mode != tuiStackCompact
	secondary := lipgloss.NewStyle().Foreground(theme.secondary)
	muted := lipgloss.NewStyle().Foreground(theme.muted)
	accent := lipgloss.NewStyle().Foreground(theme.accent).Bold(true)
	state := m.renderSandboxState(theme, selected)
	nameWidth := maxInt(1, width-lipgloss.Width(state)-2)
	lines := []string{lipgloss.NewStyle().Foreground(theme.text).Bold(true).Render(truncateText(selected.Name, nameWidth)) + "  " + state}
	summary := fmt.Sprintf("microVM · %d vCPU · %s RAM · %s", selected.DisplayCPUs(), formatMiBHuman(selected.DisplayMemoryMiB()), defaultText(selected.Runtime, "runtime unavailable"))
	if selected.ConfigError {
		summary = "! Configuration unavailable · i opens details"
	}
	lines = append(lines, muted.Render(truncateText(summary, width)))
	actions, hits := m.stackActions(theme, selected, width, len(lines))
	lines = append(lines, actions)
	if rich {
		lines = append(lines, "")
	}

	image := stackImageLabel(selected.Image)
	runtimeLabel := defaultText(selected.Runtime, "unknown") + " runtime"
	if selected.Runtime == "runsc" {
		runtimeLabel = "gVisor / runsc runtime"
	}
	storage := modernStorageSummary(selected)
	ssh := "SSH disabled"
	if selected.SSH {
		ssh = featureState(selected.State, "SSH")
	}
	ideImage := stackImageLabel(defaultText(selected.DevContainersImage, "IDE image unavailable"))
	ideDisk := formatMiBHuman(selected.DevContainersDiskMiB) + " IDE disk"
	if selected.DevContainersDiskMiB == 0 {
		ideDisk = "IDE disk size unavailable"
	}
	if selected.ConfigError {
		image, runtimeLabel, storage = "Configuration unavailable", "Runtime unavailable", "Storage unavailable"
		ideImage, ideDisk, ssh = "IDE configuration unavailable", "Storage unavailable", "Access unavailable"
	}

	inner := width - 4
	columns := selected.DevContainers && inner >= 62
	workWidth, devWidth := inner, inner
	if columns {
		workWidth = (inner - 2) / 2
		devWidth = inner - workWidth - 2
	}
	var workload, development string
	if rich {
		workload = renderStackNode(theme, workWidth, ">_ Workload", []string{
			lipgloss.NewStyle().Foreground(sandboxStateColor(theme, selected.State)).Render(stateText(selected)),
			secondary.Render(image), muted.Render(runtimeLabel), secondary.Render(storage),
		})
		development = renderStackNode(theme, devWidth, "<> Development", []string{
			secondary.Render(ideImage), muted.Render(ssh), secondary.Render(ideDisk), muted.Render("Podman Dev Containers"),
		})
	} else {
		workload = accent.Render(truncateText(">_ Workload · "+image, workWidth)) + "\n" +
			secondary.Render(truncateText(runtimeLabel, workWidth)) + "\n" + muted.Render(truncateText(storage, workWidth))
		development = accent.Render(truncateText("<> Development · "+ssh, devWidth)) + "\n" +
			secondary.Render(truncateText(ideImage, devWidth)) + "\n" + muted.Render(truncateText(ideDisk+" · Podman", devWidth))
	}
	nodes := workload
	if selected.DevContainers {
		if columns {
			nodes = lipgloss.JoinHorizontal(lipgloss.Top, workload, "  ", development)
		} else {
			gap := "\n"
			if rich {
				gap = "\n\n"
			}
			nodes += gap + development
		}
	}
	heading := accent.Render("□ microVM boundary")
	if icons {
		subtitle := "OCI workload"
		if selected.DevContainers {
			subtitle = "Workload and development environment"
		}
		heading = renderStackIconLabel(theme, tuiStackCube, "microVM boundary", subtitle, inner, true)
	}
	boundaryBody := heading + "\n" + nodes
	if rich {
		boundaryBody = heading + "\n\n" + nodes
	}
	boundary := lipgloss.NewStyle().Foreground(theme.secondary).Background(theme.panelSelected).
		Border(tuiStackBoundary).BorderForeground(theme.border).Padding(0, 1).Width(width)
	nodeY := len(lines) + 1 + lipgloss.Height(heading) + 1
	if !rich {
		nodeY--
	}
	hits = append(hits, tuiHitTarget{kind: "workload", index: m.cursor, rect: tuiRect{x: 2, y: nodeY, w: workWidth, h: lipgloss.Height(workload)}})
	lines = append(lines, strings.Split(renderSurface(boundary, theme.secondary, theme.panelSelected, boundaryBody), "\n")...)

	connector := muted.Render(strings.Repeat(" ", width/2) + "╎")
	roles := "VMM"
	if selected.Net {
		roles += " · networking"
	} else {
		roles += " · network disabled"
	}
	if selected.Shares > 0 {
		roles += " · shared filesystem"
	}
	if selected.ConfigError {
		roles = "Worker configuration unavailable"
	}
	lines = append(lines, connector)
	supervisorTitle := "Gantry supervisor + workers"
	if !icons {
		supervisorTitle = "≡ " + supervisorTitle
	}
	lines = append(lines, strings.Split(renderStackStage(theme, width, tuiLogo, supervisorTitle, roles, icons), "\n")...)
	lines = append(lines, connector)
	backend, host := stackHostBackend(runtime.GOOS)
	backendTitle := backend
	if !icons {
		backendTitle = "▣ " + backend + " · " + host + " host"
	}
	lines = append(lines, strings.Split(renderStackStage(theme, width, tuiStackChip, backendTitle, host+" · "+runtime.GOARCH+" · host virtualization", icons), "\n")...)
	if icons {
		lines = append(lines, "")
	}
	lines = append(lines, m.stackFacts(theme, selected, width, icons)...)
	return strings.Join(lines, "\n"), hits
}

func (m sandboxTUIModel) stackFacts(theme tuiTheme, selected tuiSandbox, width int, rich bool) []string {
	muted := lipgloss.NewStyle().Foreground(theme.muted)
	secondary := lipgloss.NewStyle().Foreground(theme.secondary)
	network := "Disabled"
	if selected.Net {
		network = "↓ " + formatNetworkBytes(selected.RXBytes) + "  ↑ " + formatNetworkBytes(selected.TXBytes)
	}
	access := "SSH disabled"
	if selected.SSH {
		access = featureState(selected.State, "SSH")
	}
	attached := strings.Join([]string{pluralCount(selected.Shares, "mount"), pluralCount(selected.Ports, "port"), pluralCount(selected.SecretCount, "secret")}, " · ")
	if selected.ConfigError {
		network, access, attached = "Unavailable", "Unavailable", "Unavailable"
	}
	if !rich || width < 86 {
		var lines []string
		for _, fact := range [][2]string{{"Network", network}, {"Access", access}, {"Attached", attached}} {
			lines = append(lines, muted.Width(10).Render(fact[0])+secondary.Render(truncateText(fact[1], maxInt(1, width-10))))
		}
		return lines
	}
	columnWidth := (width - 4) / 3
	networkNote := formatDashboardCount(selected.DroppedPackets) + " blocked packets"
	if selected.State != tuiRunning {
		networkNote = "Recorded totals"
	}
	accessNote := "CLI access"
	if selected.DevContainers {
		accessNote = "Dev Containers enabled"
	}
	configured := "Configured " + formatConfigTime(selected.Updated)
	if selected.ConfigError {
		networkNote, accessNote, configured = "", "", "Configuration unavailable"
	}
	columns := []string{}
	for _, fact := range [][3]string{{"Network", network, networkNote}, {"Access", access, accessNote}, {"Attached", attached, configured}} {
		body := muted.Bold(true).Render(fact[0]) + "\n" + secondary.Render(truncateText(fact[1], columnWidth)) + "\n" + muted.Render(truncateText(fact[2], columnWidth))
		columns = append(columns, lipgloss.NewStyle().Width(columnWidth).Render(body))
	}
	return strings.Split(lipgloss.JoinHorizontal(lipgloss.Top, columns[0], "  ", columns[1], "  ", columns[2]), "\n")
}
