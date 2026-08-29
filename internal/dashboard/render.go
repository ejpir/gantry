package dashboard

import (
	"fmt"
	"image/color"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
)

const (
	tuiTopPadding    = 1
	tuiMenuHeight    = tuiTopPadding + 2
	tuiFooterPadding = 1
	tuiStatusHeight  = tuiFooterPadding + 1
	tuiCardHeight    = 10
	tuiCardGapX      = 2
	tuiCardGapY      = 1
)

type tuiTheme struct {
	bg            color.Color
	panel         color.Color
	panelSelected color.Color
	panelRaised   color.Color
	text          color.Color
	secondary     color.Color
	muted         color.Color
	border        color.Color
	borderMuted   color.Color
	accent        color.Color
	accentFg      color.Color
	brand         color.Color
	brandFg       color.Color
	success       color.Color
	warning       color.Color
	error         color.Color
	info          color.Color
}

func tuiThemeFor(dark bool) tuiTheme {
	if dark {
		return tuiTheme{
			bg:            lipgloss.Color("#16161E"),
			panel:         lipgloss.Color("#1A1B26"),
			panelSelected: lipgloss.Color("#202337"),
			panelRaised:   lipgloss.Color("#292E42"),
			text:          lipgloss.Color("#E6E9F0"),
			secondary:     lipgloss.Color("#C9CFDB"),
			muted:         lipgloss.Color("#6B7386"),
			border:        lipgloss.Color("#4A5266"),
			borderMuted:   lipgloss.Color("#3A4152"),
			accent:        lipgloss.Color("#7F77DD"),
			accentFg:      lipgloss.Color("#EEEDFE"),
			brand:         lipgloss.Color("#7F77DD"),
			brandFg:       lipgloss.Color("#EEEDFE"),
			success:       lipgloss.Color("#5DCAA5"),
			warning:       lipgloss.Color("#EFA027"),
			error:         lipgloss.Color("#D4537E"),
			info:          lipgloss.Color("#7F77DD"),
		}
	}
	return tuiTheme{
		bg:            lipgloss.Color("#F7F8FC"),
		panel:         lipgloss.Color("#FFFFFF"),
		panelSelected: lipgloss.Color("#EDF3FF"),
		panelRaised:   lipgloss.Color("#E4E9F2"),
		text:          lipgloss.Color("#2C2C2A"),
		secondary:     lipgloss.Color("#4B4B47"),
		muted:         lipgloss.Color("#888780"),
		border:        lipgloss.Color("#9D9B93"),
		borderMuted:   lipgloss.Color("#B4B2A9"),
		accent:        lipgloss.Color("#534AB7"),
		accentFg:      lipgloss.Color("#EEEDFE"),
		brand:         lipgloss.Color("#534AB7"),
		brandFg:       lipgloss.Color("#EEEDFE"),
		success:       lipgloss.Color("#0F6E56"),
		warning:       lipgloss.Color("#854F0B"),
		error:         lipgloss.Color("#993556"),
		info:          lipgloss.Color("#534AB7"),
	}
}

type tuiRect struct{ x, y, w, h int }

func (r tuiRect) contains(x, y int) bool {
	return x >= r.x && x < r.x+r.w && y >= r.y && y < r.y+r.h
}

type tuiDashboardLayout struct {
	screenWidth, width, height int
	contentX, contentY         int
	contentHeight              int
	cols                       int
	cardWidth                  int
	cardHeight                 int
	marginX                    int
	gapX, gapY                 int
	visibleRows                int
	emptyVerticalOffset        int
}

func (m sandboxTUIModel) dashboardLayout() tuiDashboardLayout {
	screenWidth := maxInt(24, m.width)
	height := maxInt(tuiMenuHeight+tuiStatusHeight+1, m.height)
	contentX := 0
	width := screenWidth
	contentY := tuiMenuHeight
	contentHeight := maxInt(1, height-contentY-tuiStatusHeight)
	cardHeight := minInt(tuiCardHeight, contentHeight)
	cardHeight = maxInt(5, cardHeight)
	if cardHeight > contentHeight {
		cardHeight = contentHeight
	}

	available := maxInt(20, width-4)
	cols := clampInt((available+2)/32, 1, 3)
	for cols > 1 && (available-tuiCardGapX*(cols-1))/cols < 28 {
		cols--
	}
	marginX := 2
	cardWidth := (available - tuiCardGapX*(cols-1)) / cols
	emptyOffset := 0
	if len(m.sandboxes) == 0 && !m.loading {
		cols = 1
		cardWidth = minInt(38, available)
		marginX = maxInt(1, (width-cardWidth)/2)
		emptyOffset = maxInt(0, (contentHeight-cardHeight)/2)
	}
	visibleRows := maxInt(1, (contentHeight+tuiCardGapY)/(cardHeight+tuiCardGapY))
	if emptyOffset > 0 {
		visibleRows = 1
	}
	return tuiDashboardLayout{
		screenWidth:         screenWidth,
		width:               width,
		height:              height,
		contentX:            contentX,
		contentY:            contentY,
		contentHeight:       contentHeight,
		cols:                cols,
		cardWidth:           cardWidth,
		cardHeight:          cardHeight,
		marginX:             marginX,
		gapX:                tuiCardGapX,
		gapY:                tuiCardGapY,
		visibleRows:         visibleRows,
		emptyVerticalOffset: emptyOffset,
	}
}

func (l tuiDashboardLayout) totalRows(entries int) int {
	return maxInt(1, (entries+l.cols-1)/l.cols)
}

func (l tuiDashboardLayout) maxScrollRow(entries int) int {
	return maxInt(0, l.totalRows(entries)-l.visibleRows)
}

func (l tuiDashboardLayout) cardRect(index, scrollRow int) tuiRect {
	row, col := index/l.cols, index%l.cols
	return tuiRect{
		x: l.contentX + l.marginX + col*(l.cardWidth+l.gapX),
		y: l.contentY + l.emptyVerticalOffset + (row-scrollRow)*(l.cardHeight+l.gapY),
		w: l.cardWidth,
		h: l.cardHeight,
	}
}

func (m *sandboxTUIModel) View() tea.View {
	theme := tuiThemeFor(m.dark)
	view := tea.NewView(m.renderScreen(theme))
	view.AltScreen = true
	view.WindowTitle = "Gantry — " + pageDisplayTitle(m.page)
	view.MouseMode = tea.MouseModeCellMotion
	view.ReportFocus = true
	view.BackgroundColor = theme.bg
	view.ForegroundColor = theme.text
	return view
}

func (m *sandboxTUIModel) renderScreen(theme tuiTheme) string {
	layout := m.dashboardLayout()
	header := m.renderMenuBar(theme, layout.screenWidth)
	var body string
	switch m.page {
	case tuiOverviewPage:
		body = m.renderOperationalDashboard(theme, layout)
	case tuiTrafficPage:
		body = m.renderTrafficView(theme, layout)
	case tuiRulesPage:
		body = m.renderRulesView(theme, layout)
	case tuiMountsPage:
		body = m.renderMountsView(theme, layout)
	case tuiPortsPage:
		body = m.renderPortsView(theme, layout)
	case tuiSecretsPage:
		body = m.renderSecretsView(theme, layout)
	case tuiMCPPage:
		body = m.renderMCPView(theme, layout)
	case tuiPacketsPage:
		body = m.renderPacketsView(theme, layout)
	case tuiImagesPage:
		body = m.renderImagesView(theme, layout)
	default:
		if m.usesMasterDetail(layout) {
			body = m.renderSandboxMasterDetail(theme, layout)
		} else {
			body = m.renderCardGrid(theme, layout)
		}
	}
	status := m.renderStatusBar(theme, layout.screenWidth)

	sections := []string{header, body, status}
	base := lipgloss.JoinVertical(lipgloss.Left, sections...)
	baseStyle := lipgloss.NewStyle().
		Foreground(theme.text).
		Background(theme.bg).
		Width(layout.screenWidth).
		Height(layout.height).
		MaxHeight(layout.height)
	base = renderSurface(baseStyle, theme.text, theme.bg, base)

	if m.dialog != tuiNoDialog {
		base = lipgloss.NewStyle().Faint(true).Render(base)
	}
	layers := []*lipgloss.Layer{lipgloss.NewLayer(base).X(0).Y(0).Z(0)}

	if indicator := m.renderActiveScrollbar(theme, layout); indicator != "" {
		layers = append(layers, lipgloss.NewLayer(indicator).X(layout.contentX+layout.width-1).Y(layout.contentY).Z(1))
	}
	if m.toast != nil {
		toast := m.renderToast(theme)
		toastWidth := lipgloss.Width(toast)
		z := 2
		if m.dialog != tuiNoDialog {
			z = 4
		}
		layers = append(layers, lipgloss.NewLayer(toast).
			X(maxInt(0, layout.screenWidth-toastWidth-2)).Y(tuiMenuHeight+1).Z(z))
	}
	// Publish the hit map from this exact render pass. All geometry in the map
	// is shared with the components rendered above, including responsive mode,
	// scrolling, responsive navigation, and component composition.
	m.dashboardHits = m.dashboardHitTargets(layout)

	if m.dialog != tuiNoDialog {
		dialog := m.renderDialog(theme)
		bounds := m.dialogBounds(m.dialog)
		layers = append(layers, lipgloss.NewLayer(dialog).X(bounds.x).Y(bounds.y).Z(3))
	}
	return lipgloss.NewCompositor(layers...).Render()
}

func (m sandboxTUIModel) renderMenuBar(theme tuiTheme, width int) string {
	brand := lipgloss.NewStyle().Bold(true).Foreground(theme.brandFg).Background(theme.brand).Padding(0, 1).Render("GANTRY")
	var left strings.Builder
	left.WriteString("  ")
	left.WriteString(brand)
	position := 2 + lipgloss.Width(brand)
	tabs := m.tabRects(width)
	for _, tab := range tabs {
		if tab.x > position {
			left.WriteString(strings.Repeat(" ", tab.x-position))
		}
		style := lipgloss.NewStyle().Foreground(theme.muted)
		if tab.active {
			style = style.Foreground(theme.text).Bold(true).Underline(true)
		}
		left.WriteString(style.Render(tab.label))
		position = tab.x + tab.w
	}

	summary := m.tabSummary(theme)
	if m.refreshVisible {
		summary = m.spinner.View() + lipgloss.NewStyle().Foreground(theme.muted).Render(" syncing")
	}
	right := summary
	if m.updateStatus.Available {
		update := lipgloss.NewStyle().Bold(true).Foreground(theme.warning).Render("U ↑ " + m.updateStatus.Latest)
		combined := update
		if summary != "" {
			combined = summary + lipgloss.NewStyle().Foreground(theme.muted).Render("  ·  ") + update
		}
		if lipgloss.Width(left.String())+lipgloss.Width(combined)+3 <= width {
			right = combined
		} else {
			right = update
		}
	}
	line := left.String()
	if right != "" && lipgloss.Width(line)+lipgloss.Width(right)+3 <= width {
		line = joinSides(line, right+"  ", width)
	} else {
		line = truncateANSI(line, width)
	}
	content := strings.Repeat("\n", tuiTopPadding) + line
	style := lipgloss.NewStyle().Foreground(theme.text).Background(theme.bg).Width(width).Height(tuiMenuHeight).MaxHeight(tuiMenuHeight)
	return renderSurface(style, theme.text, theme.bg, content)
}

type tuiMenuItem struct {
	id    string
	key   string
	label string
}

func (m sandboxTUIModel) menuItems(_ int) []tuiMenuItem {
	if !m.updateStatus.Available {
		return nil
	}
	return []tuiMenuItem{{id: "update", key: "U", label: "↑ " + m.updateStatus.Latest}}
}

func (m sandboxTUIModel) menuItemRects(width int) map[string]tuiRect {
	items := m.menuItems(width)
	rects := make(map[string]tuiRect, len(items))
	lines := strings.Split(ansi.Strip(m.renderMenuBar(tuiThemeFor(m.dark), width)), "\n")
	if len(lines) <= tuiTopPadding {
		return rects
	}
	headerLine := lines[tuiTopPadding]
	for _, item := range items {
		label := item.key + " " + item.label
		if offset := strings.LastIndex(headerLine, label); offset >= 0 {
			x := lipgloss.Width(headerLine[:offset])
			rects[item.id] = tuiRect{x: x, y: tuiTopPadding, w: lipgloss.Width(label), h: 1}
		}
	}
	return rects
}

type tuiTabRect struct {
	page   tuiPage
	x, w   int
	label  string
	active bool
}

func (m sandboxTUIModel) tabRects(width int) []tuiTabRect {
	const navigationStart = 12 // two-cell inset, eight-cell brand, two-cell gap
	currentLabel := "‹ " + strings.ToLower(pageDisplayTitle(m.page)) + " ›"
	compactCurrent := func() []tuiTabRect {
		label := truncateText(currentLabel, maxInt(1, width-navigationStart))
		return []tuiTabRect{{page: m.page, x: navigationStart, w: lipgloss.Width(label), label: label, active: true}}
	}
	items := []tuiTabRect{
		{page: tuiOverviewPage, label: "overview", active: m.page == tuiOverviewPage},
		{page: tuiSandboxesPage, label: "sandboxes", active: m.page == tuiSandboxesPage},
		{page: tuiTrafficPage, label: "traffic", active: m.page == tuiTrafficPage},
		{page: tuiRulesPage, label: "rules", active: m.page == tuiRulesPage},
		{page: tuiPortsPage, label: "ports", active: m.page == tuiPortsPage},
		{page: tuiPacketsPage, label: "packets", active: m.page == tuiPacketsPage},
		{page: tuiMountsPage, label: "mounts", active: m.page == tuiMountsPage},
		{page: tuiSecretsPage, label: "secrets", active: m.page == tuiSecretsPage},
		{page: tuiMCPPage, label: "mcp", active: m.page == tuiMCPPage},
		{page: tuiImagesPage, label: "images", active: m.page == tuiImagesPage},
	}
	x := navigationStart
	for index := range items {
		items[index].x = x
		items[index].w = lipgloss.Width(items[index].label)
		x += items[index].w + 2
	}
	actionWidth := 0
	for index, item := range m.menuItems(width) {
		if index > 0 {
			actionWidth += 3
		}
		actionWidth += lipgloss.Width(item.key + " " + item.label)
	}
	if x+actionWidth+2 > width {
		return compactCurrent()
	}
	return items
}

func (m sandboxTUIModel) tabSummary(theme tuiTheme) string {
	switch m.page {
	case tuiOverviewPage:
		running, allocatedVCPUs := 0, 0
		for _, sandbox := range m.sandboxes {
			allocatedVCPUs += maxInt(1, sandbox.VCPUs)
			if sandbox.State == tuiRunning {
				running++
			}
		}
		hostVCPUs := maxInt(1, m.limits.MaxVCPUs)
		return lipgloss.NewStyle().Foreground(theme.success).Render("●") + lipgloss.NewStyle().Foreground(theme.secondary).Render(fmt.Sprintf(" %d running · host %d/%d vCPU", running, allocatedVCPUs, hostVCPUs))
	case tuiTrafficPage:
		var tx, rx, blocked uint64
		for _, sandbox := range m.sandboxes {
			tx += sandbox.TXBytes
			rx += sandbox.RXBytes
			blocked += sandbox.DroppedPackets
		}
		summary := lipgloss.NewStyle().Foreground(theme.secondary).Render("↑" + formatBytes(tx) + "  ↓" + formatBytes(rx))
		if blocked > 0 {
			summary += "  " + lipgloss.NewStyle().Foreground(theme.error).Render(fmt.Sprintf("%d blocked", blocked))
		}
		return summary
	case tuiRulesPage:
		allowed, denied := 0, 0
		for _, rule := range m.rules {
			switch rule.Action {
			case "allow":
				allowed++
			case "deny":
				denied++
			}
		}
		return lipgloss.NewStyle().Foreground(theme.success).Render(fmt.Sprintf("%d allow", allowed)) + "  " +
			lipgloss.NewStyle().Foreground(theme.error).Render(fmt.Sprintf("%d deny", denied))
	case tuiMountsPage:
		readOnly := 0
		for _, mount := range m.mounts {
			if mount.ReadOnly {
				readOnly++
			}
		}
		return lipgloss.NewStyle().Foreground(theme.secondary).Render(fmt.Sprintf("%d total  •  %d read-only", len(m.mounts), readOnly))
	case tuiPortsPage:
		bound := 0
		for _, port := range m.ports {
			if port.State == "bound" {
				bound++
			}
		}
		return lipgloss.NewStyle().Foreground(theme.secondary).Render(fmt.Sprintf("%d bound  •  %d saved", bound, len(m.ports)-bound))
	case tuiSecretsPage:
		loaded := 0
		for _, item := range m.secrets {
			if item.State == "loaded" {
				loaded++
			}
		}
		return lipgloss.NewStyle().Foreground(theme.secondary).Render(fmt.Sprintf("%d names  •  %d loaded", len(m.secrets), loaded))
	case tuiMCPPage:
		remotes, restart := 0, 0
		for _, server := range m.mcpServers {
			if server.Type == "remote" {
				remotes++
			}
			if server.State == "restart" {
				restart++
			}
		}
		summary := fmt.Sprintf("%d servers  •  %d remote", len(m.mcpServers), remotes)
		if restart > 0 {
			summary += fmt.Sprintf("  •  %d restart", restart)
		}
		return lipgloss.NewStyle().Foreground(theme.secondary).Render(summary)
	case tuiPacketsPage:
		state := "live"
		if m.packetPaused {
			state = "paused"
		}
		return lipgloss.NewStyle().Foreground(theme.secondary).Render(fmt.Sprintf("%d captured  •  %d evicted  •  %s", len(m.packets), m.packetEvicted, state))
	case tuiImagesPage:
		var total int64
		for _, row := range m.images {
			total += row.Size
		}
		summary := fmt.Sprintf("%d images  •  %s cached", len(m.images), formatBytes(uint64(maxInt(0, int(total)))))
		if m.imageSection == tuiImageSectionCredentials {
			stored := 0
			for _, row := range m.registries {
				if row.HasSecret {
					stored++
				}
			}
			summary = fmt.Sprintf("%d registries  •  %d logins", len(m.registries), stored)
		}
		return lipgloss.NewStyle().Foreground(theme.secondary).Render(summary)
	default:
		running, starting := 0, 0
		for _, sandbox := range m.sandboxes {
			switch sandbox.State {
			case tuiRunning:
				running++
			case tuiStarting:
				starting++
			}
		}
		right := lipgloss.NewStyle().Foreground(theme.success).Render("●") +
			lipgloss.NewStyle().Foreground(theme.secondary).Render(fmt.Sprintf(" %d running", running))
		if starting > 0 {
			right += "  " + lipgloss.NewStyle().Foreground(theme.warning).Render("◐") +
				lipgloss.NewStyle().Foreground(theme.secondary).Render(fmt.Sprintf(" %d starting", starting))
		}
		return right
	}
}

func (m sandboxTUIModel) renderCardGrid(theme tuiTheme, layout tuiDashboardLayout) string {
	if m.loading {
		loading := m.spinner.View() + " " + lipgloss.NewStyle().Foreground(theme.secondary).Render("Discovering local sandboxes…")
		style := lipgloss.NewStyle().
			Foreground(theme.text).
			Background(theme.bg).
			Width(layout.width).
			Height(layout.contentHeight).
			Align(lipgloss.Center, lipgloss.Center)
		return renderSurface(style, theme.text, theme.bg, loading)
	}

	var rows []string
	if layout.emptyVerticalOffset > 0 {
		rows = append(rows, strings.Repeat("\n", layout.emptyVerticalOffset-1))
	}
	startRow := m.scrollRow
	endRow := minInt(layout.totalRows(m.entryCount()), startRow+layout.visibleRows)
	for row := startRow; row < endRow; row++ {
		var cards []string
		for col := 0; col < layout.cols; col++ {
			index := row*layout.cols + col
			if index >= m.entryCount() {
				break
			}
			if index == len(m.sandboxes) {
				cards = append(cards, m.renderNewSandboxCard(theme, layout, index == m.cursor))
			} else {
				cards = append(cards, m.renderSandboxCard(theme, layout, m.sandboxes[index], index == m.cursor))
			}
		}
		rowView := lipgloss.JoinHorizontal(lipgloss.Top, intersperse(cards, strings.Repeat(" ", layout.gapX))...)
		rows = append(rows, padLeftBlock(rowView, layout.marginX))
		if row+1 < endRow {
			rows = append(rows, strings.Repeat("\n", layout.gapY+1))
		}
	}
	content := strings.Join(rows, "")
	style := lipgloss.NewStyle().
		Foreground(theme.text).
		Background(theme.bg).
		Width(layout.width).
		Height(layout.contentHeight).
		MaxHeight(layout.contentHeight)
	return renderSurface(style, theme.text, theme.bg, content)
}

func (m sandboxTUIModel) renderSandboxCard(theme tuiTheme, layout tuiDashboardLayout, sandbox tuiSandbox, selected bool) string {
	border := theme.borderMuted
	background := theme.panel
	if selected {
		border = theme.accent
		background = theme.panelSelected
	}
	if sandbox.ConfigError && !selected {
		border = theme.warning
	}

	innerWidth := maxInt(1, layout.cardWidth-4)
	state := m.renderSandboxState(theme, sandbox)
	nameStyle := lipgloss.NewStyle().Bold(true).Foreground(theme.text)
	if selected {
		nameStyle = nameStyle.Foreground(theme.accent)
	}
	header := joinSides(nameStyle.Render(truncateText(sandbox.Name, maxInt(4, innerWidth-lipgloss.Width(state)-1))), state, innerWidth)
	separator := lipgloss.NewStyle().Foreground(theme.borderMuted).Render(strings.Repeat("─", innerWidth))

	image := labeledValue(theme, "image", sandbox.Image, innerWidth)
	runtimeName := sandbox.Runtime
	if runtimeName == "" {
		runtimeName = "unknown"
	}
	compute := fmt.Sprintf("%s · %dc · %dMB", runtimeName, maxInt(1, sandbox.VCPUs), sandbox.MemMB)
	computeLine := labeledValue(theme, "compute", compute, innerWidth)
	storageLine := labeledValue(theme, "storage", sandboxStorageSummary(sandbox, false), innerWidth)
	network := "offline"
	if sandbox.Net {
		network = "connected"
		if sandbox.TXBytes > 0 || sandbox.RXBytes > 0 {
			network = "↑" + formatBytes(sandbox.TXBytes) + " ↓" + formatBytes(sandbox.RXBytes)
		}
		if sandbox.DroppedPackets > 0 {
			network += fmt.Sprintf(" !%d", sandbox.DroppedPackets)
		}
	}
	if sandbox.ConfigError {
		network = "configuration unavailable"
	}
	networkLine := labeledValue(theme, "network", network, innerWidth)
	actions := m.renderCardActions(theme, sandbox, selected, innerWidth)

	lines := []string{header, separator, image, computeLine, storageLine, networkLine, separator, actions}
	if layout.cardHeight < tuiCardHeight {
		lines = compactCardLines(lines, maxInt(1, layout.cardHeight-2))
	}
	content := strings.Join(lines, "\n")
	style := lipgloss.NewStyle().
		Foreground(theme.text).
		Background(background).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(border).
		Padding(0, 1).
		Width(layout.cardWidth).
		Height(layout.cardHeight).
		MaxHeight(layout.cardHeight)
	return renderSurface(style, theme.text, background, content)
}

func (m sandboxTUIModel) renderNewSandboxCard(theme tuiTheme, layout tuiDashboardLayout, selected bool) string {
	border := theme.borderMuted
	background := theme.panel
	if selected {
		border, background = theme.accent, theme.panelSelected
	}
	dashed := lipgloss.Border{
		Top: "┄", Bottom: "┄", Left: "┆", Right: "┆",
		TopLeft: "╭", TopRight: "╮", BottomLeft: "╰", BottomRight: "╯",
	}
	plus := lipgloss.NewStyle().Bold(true).Foreground(theme.accent).Render("＋")
	title := lipgloss.NewStyle().Bold(true).Foreground(theme.text).Render("New Sandbox")
	hint := lipgloss.NewStyle().Foreground(theme.muted).Render("n / enter to create")
	contentLines := []string{plus, title, hint}
	availableLines := maxInt(1, layout.cardHeight-2)
	if availableLines < len(contentLines) {
		contentLines = contentLines[len(contentLines)-availableLines:]
	}
	content := lipgloss.JoinVertical(lipgloss.Center, contentLines...)
	style := lipgloss.NewStyle().
		Foreground(theme.text).
		Background(background).
		Border(dashed).
		BorderForeground(border).
		Width(layout.cardWidth).
		Height(layout.cardHeight).
		MaxHeight(layout.cardHeight).
		Align(lipgloss.Center, lipgloss.Center)
	return renderSurface(style, theme.text, background, content)
}

func (m sandboxTUIModel) renderSandboxState(theme tuiTheme, sandbox tuiSandbox) string {
	if m.busyName == sandbox.Name {
		return m.spinner.View() + " " + lipgloss.NewStyle().Bold(true).Foreground(theme.warning).Render(busyLabel(m.busyAction))
	}
	switch sandbox.State {
	case tuiRunning:
		return lipgloss.NewStyle().Bold(true).Foreground(theme.success).Render("● RUNNING")
	case tuiStarting:
		return m.spinner.View() + " " + lipgloss.NewStyle().Bold(true).Foreground(theme.warning).Render("STARTING")
	default:
		return lipgloss.NewStyle().Foreground(theme.muted).Render("○ STOPPED")
	}
}

type tuiCardAction struct {
	key, label, action string
}

func sandboxCardActions(sandbox tuiSandbox) []tuiCardAction {
	if sandbox.State == tuiRunning {
		return []tuiCardAction{{"↵", "open", "primary"}, {"s", "top", "toggle"}, {"e", "dit", "edit"}, {"d", "elete", "delete"}}
	}
	return []tuiCardAction{{"↵", "start", "primary"}, {"e", "dit", "edit"}, {"d", "elete", "delete"}}
}

func (m sandboxTUIModel) renderCardActions(theme tuiTheme, sandbox tuiSandbox, selected bool, width int) string {
	if m.busyName == sandbox.Name {
		return truncateANSI(m.spinner.View()+" "+lipgloss.NewStyle().Foreground(theme.secondary).Render(strings.ToLower(busyLabel(m.busyAction))+"…"), width)
	}
	var rendered []string
	for _, action := range sandboxCardActions(sandbox) {
		keyColor := theme.muted
		descColor := theme.muted
		if selected {
			keyColor = theme.accent
			descColor = theme.secondary
		}
		key := lipgloss.NewStyle().Bold(true).Foreground(keyColor).Render(action.key)
		desc := lipgloss.NewStyle().Foreground(descColor).Render(action.label)
		rendered = append(rendered, key+desc)
	}
	return truncateANSI(strings.Join(rendered, "  "), width)
}

func (m sandboxTUIModel) renderStatusBar(theme tuiTheme, width int) string {
	innerWidth := maxInt(1, width-4)
	position := m.pagePosition()
	updated := relativeUpdate(m.lastUpdate)
	if updated == "" {
		updated = "updated never"
	}
	rightText := updated
	if m.page != tuiOverviewPage && width >= 72 {
		rightText += "  ·  " + position
	}
	right := lipgloss.NewStyle().Foreground(theme.muted).Render(rightText)

	var left string
	budget := maxInt(1, innerWidth-lipgloss.Width(right)-1)
	if m.busyAction != "" {
		if m.busyProgress != "" {
			left = truncateANSI(lipgloss.NewStyle().Foreground(theme.text).Render(m.busyProgress), budget)
		} else {
			left = m.spinner.View() + " " + lipgloss.NewStyle().Foreground(theme.text).Render(strings.ToLower(busyLabel(m.busyAction))+" "+m.busyName+"…")
		}
	} else {
		separator := lipgloss.NewStyle().Foreground(theme.border).Render("  •  ")
		var parts []string
		for _, hint := range m.contextHints() {
			key := lipgloss.NewStyle().Bold(true).Foreground(theme.accent).Render(hint[0])
			desc := lipgloss.NewStyle().Foreground(theme.secondary).Render(hint[1])
			candidate := strings.Join(append(parts, key+" "+desc), separator)
			if len(parts) > 0 && lipgloss.Width(candidate) > budget {
				break
			}
			parts = append(parts, key+" "+desc)
			if lipgloss.Width(candidate) > budget {
				break
			}
		}
		left = truncateANSI(strings.Join(parts, separator), budget)
	}

	line := joinSides(left, right, innerWidth)
	content := strings.Repeat("\n", tuiFooterPadding) + line
	style := lipgloss.NewStyle().
		Foreground(theme.secondary).
		Background(theme.bg).
		Padding(0, 2).
		Width(width).
		Height(tuiStatusHeight).
		MaxHeight(tuiStatusHeight)
	return renderSurface(style, theme.secondary, theme.bg, content)
}

func (m sandboxTUIModel) contextHints() [][2]string {
	switch m.page {
	case tuiOverviewPage:
		if len(m.sandboxes) == 0 {
			return [][2]string{{"enter", "create"}, {"n", "new"}, {"r", "refresh"}, {"?", "help"}}
		}
		return [][2]string{{"enter", "open"}, {"t", "traffic"}, {"n", "new"}, {"?", "help"}}
	case tuiTrafficPage:
		return [][2]string{{"↑/↓", "inspect"}, {"a", "allow/block"}, {"r", "remove rule"}, {"R", "refresh"}, {"tab", "next view"}, {"?", "help"}}
	case tuiRulesPage:
		return [][2]string{{"↑/↓", "inspect"}, {"d", "remove entry"}, {"e", "edit policy"}, {"tab", "next view"}, {"r", "refresh"}, {"?", "help"}}
	case tuiMountsPage:
		return [][2]string{{"a", "add share"}, {"d", "remove share"}, {"r", "replace"}, {"R", "refresh"}, {"tab", "next view"}, {"?", "help"}}
	case tuiPortsPage:
		return [][2]string{{"p", "publish"}, {"d", "unpublish"}, {"tab", "next view"}, {"r", "refresh"}, {"esc", "sandboxes"}, {"?", "help"}}
	case tuiSecretsPage:
		return [][2]string{{"a", "add secret"}, {"d", "delete"}, {"tab", "next view"}, {"r", "refresh"}, {"esc", "sandboxes"}, {"?", "help"}}
	case tuiMCPPage:
		return [][2]string{{"a", "add remote"}, {"f", "filesystem"}, {"e", "edit"}, {"d", "remove"}, {"tab", "next view"}, {"?", "help"}}
	case tuiPacketsPage:
		return [][2]string{{"↑/↓", "select"}, {"d", "details"}, {"space", "pause"}, {"c", "clear"}, {"tab", "next view"}, {"?", "help"}}
	case tuiImagesPage:
		if m.imageSection == tuiImageSectionCredentials {
			return [][2]string{{"a", "login"}, {"d", "logout"}, {"s", "images"}, {"tab", "next view"}, {"r", "refresh"}, {"?", "help"}}
		}
		return [][2]string{{"p", "pull"}, {"d", "remove"}, {"u", "prune"}, {"s", "registries"}, {"tab", "next view"}, {"?", "help"}}
	}
	if m.onNewCard() {
		return [][2]string{{"enter", "create"}, {"r", "refresh"}, {"?", "help"}, {"q", "quit"}}
	}
	selected := m.selected()
	if selected != nil && selected.State == tuiRunning {
		return [][2]string{{"enter", "open"}, {"s", "stop"}, {"e", "edit"}, {"i", "details"}, {"d", "remove"}, {"?", "help"}}
	}
	return [][2]string{{"enter", "start"}, {"s", "start"}, {"e", "edit"}, {"i", "details"}, {"d", "remove"}, {"?", "help"}}
}

func (m sandboxTUIModel) pagePosition() string {
	if m.page == tuiOverviewPage {
		if len(m.sandboxes) == 0 {
			return "0/0"
		}
		return fmt.Sprintf("%d/%d", m.cursor+1, len(m.sandboxes))
	}
	if m.page == tuiSandboxesPage {
		return fmt.Sprintf("%d/%d", m.cursor+1, m.entryCount())
	}
	cursor, _, count := m.tableState()
	if count == 0 || cursor == nil {
		return "0/0"
	}
	return fmt.Sprintf("%d/%d", *cursor+1, count)
}

func (m sandboxTUIModel) renderCardScrollbar(theme tuiTheme, layout tuiDashboardLayout) string {
	totalRows := layout.totalRows(m.entryCount())
	if totalRows <= layout.visibleRows || layout.contentHeight < 2 {
		return ""
	}
	trackHeight := layout.contentHeight
	thumbHeight := maxInt(1, trackHeight*layout.visibleRows/totalRows)
	maxScroll := maxInt(1, totalRows-layout.visibleRows)
	thumbTop := (trackHeight - thumbHeight) * m.scrollRow / maxScroll
	lines := make([]string, trackHeight)
	for i := range lines {
		glyph, fg := "│", theme.borderMuted
		if i >= thumbTop && i < thumbTop+thumbHeight {
			glyph, fg = "┃", theme.accent
		}
		lines[i] = lipgloss.NewStyle().Foreground(fg).Background(theme.bg).Render(glyph)
	}
	return strings.Join(lines, "\n")
}

func (m sandboxTUIModel) toastBounds(theme tuiTheme) tuiRect {
	toast := m.renderToast(theme)
	width, height := lipgloss.Width(toast), lipgloss.Height(toast)
	return tuiRect{x: maxInt(0, m.width-width-2), y: tuiMenuHeight + 1, w: width, h: height}
}

func (m sandboxTUIModel) renderToast(theme tuiTheme) string {
	if m.toast == nil {
		return ""
	}
	border, icon := theme.info, "●"
	switch m.toast.kind {
	case tuiToastSuccess:
		border, icon = theme.success, "✓"
	case tuiToastWarning:
		border, icon = theme.warning, "!"
	case tuiToastError:
		border, icon = theme.error, "×"
	}
	width := clampInt(m.width-4, 20, 48)
	innerWidth := maxInt(8, width-4)
	title := lipgloss.NewStyle().Bold(true).Foreground(border).Render(icon + " " + m.toast.title)
	title = joinSides(title, lipgloss.NewStyle().Foreground(theme.muted).Render("×"), innerWidth)
	body := lipgloss.Wrap(m.toast.body, innerWidth, "")
	body = lipgloss.NewStyle().Foreground(theme.secondary).MaxHeight(2).Render(body)
	content := title
	if strings.TrimSpace(m.toast.body) != "" {
		content += "\n" + body
	}
	style := lipgloss.NewStyle().
		Foreground(theme.text).
		Background(theme.panel).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(border).
		Padding(0, 1).
		Width(width).
		MaxHeight(5)
	return renderSurface(style, theme.text, theme.panel, content)
}

// dialogMeasured renders the dialog body ONCE and derives the geometry
// from it. dialogSize and renderDialog both need the same wrapped content;
// rendering it twice per frame doubled the cost of every dialog repaint.
func (m sandboxTUIModel) dialogMeasured(theme tuiTheme, kind tuiDialog) (width, height int, content string, border color.Color) {
	idealWidth := 62
	switch kind {
	case tuiHelpDialog:
		idealWidth = 72
	case tuiInfoDialog:
		idealWidth = 68
	case tuiPacketDetailDialog:
		idealWidth = 96
	case tuiRemoveDialog, tuiShareRemoveDialog, tuiPortUnpublishDialog, tuiRuleRemoveDialog, tuiSecretRemoveDialog, tuiMCPRemoveDialog, tuiUpdateDialog, tuiImageRemoveDialog, tuiImagePruneDialog, tuiRegistryLogoutDialog:
		idealWidth = 54
	case tuiCreateDialog:
		idealWidth = 72
	case tuiEditDialog:
		idealWidth = 64
	case tuiPortPublishDialog:
		idealWidth = 68
	case tuiShareAddDialog:
		idealWidth = 68
	case tuiNetworkPolicyDialog, tuiRuleAddDialog, tuiSecretAddDialog, tuiMCPRemoteDialog, tuiMCPFilesystemDialog, tuiImagePullDialog, tuiRegistryLoginDialog:
		idealWidth = 68
	}
	width = minInt(idealWidth, maxInt(24, m.width-4))
	innerWidth := maxInt(10, width-6)
	content, border = m.dialogContent(theme, kind, innerWidth)
	content = lipgloss.Wrap(content, innerWidth, "")
	// Border and vertical padding consume four rows. Measuring the actual
	// wrapped body keeps geometry, overlay bounds, and mouse hit testing in
	// agreement even when labels or paths wrap at narrower widths.
	height = minInt(maxInt(8, lipgloss.Height(content)+4), maxInt(8, m.height-2))
	return width, height, content, border
}

func (m sandboxTUIModel) dialogSize(kind tuiDialog) (int, int) {
	width, height, _, _ := m.dialogMeasured(tuiThemeFor(m.dark), kind)
	return width, height
}

// Forms benefit from visual separation between sections, but retaining every
// control is more important in a short terminal. Compact layouts keep the same
// fields and keyboard order with the blank separator rows removed.
func (m sandboxTUIModel) formDialogsSpacious() bool {
	return m.height >= 35 && !m.shareSandbox.open && !m.portSandbox.open && !m.policySandbox.open && !m.ruleSandbox.open && !m.secretSandbox.open && !m.mcpSandbox.open
}

func (m sandboxTUIModel) formSectionGap() string {
	if m.dialog == tuiMCPRemoteDialog {
		return "\n"
	}
	if m.formDialogsSpacious() {
		return "\n\n"
	}
	return "\n"
}

func (m sandboxTUIModel) dialogBounds(kind tuiDialog) tuiRect {
	width, height := m.dialogSize(kind)
	return tuiRect{
		x: maxInt(0, (m.width-width)/2),
		y: maxInt(0, (m.height-height)/2),
		w: width,
		h: height,
	}
}

func (m sandboxTUIModel) renderDialog(theme tuiTheme) string {
	width, height, content, border := m.dialogMeasured(theme, m.dialog)
	viewport := maxInt(1, height-4)
	total := lipgloss.Height(content)
	maxScroll := maxInt(0, total-viewport)
	scroll := clampInt(m.dialogScroll, 0, maxScroll)
	content = sliceBlockLines(content, scroll, viewport)
	style := lipgloss.NewStyle().
		Foreground(theme.text).
		Background(theme.panel).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(border).
		Padding(1, 2).
		Width(width).
		Height(height).
		MaxHeight(height)
	base := renderSurface(style, theme.text, theme.panel, content)
	if maxScroll == 0 {
		return base
	}
	scrollbar := renderDialogScrollbar(theme, viewport, total, scroll)
	return lipgloss.NewCompositor(
		lipgloss.NewLayer(base).X(0).Y(0).Z(0),
		lipgloss.NewLayer(scrollbar).X(width-2).Y(2).Z(1),
	).Render()
}

func renderDialogScrollbar(theme tuiTheme, viewport, total, scroll int) string {
	if viewport <= 0 || total <= viewport {
		return ""
	}
	thumbHeight := maxInt(1, viewport*viewport/total)
	maxScroll := total - viewport
	thumbStart := 0
	if maxScroll > 0 {
		thumbStart = (viewport - thumbHeight) * scroll / maxScroll
	}
	track := lipgloss.NewStyle().Foreground(theme.borderMuted).Background(theme.panel)
	thumb := lipgloss.NewStyle().Foreground(theme.accent).Background(theme.panel)
	lines := make([]string, viewport)
	for i := range lines {
		lines[i] = track.Render("│")
		if i >= thumbStart && i < thumbStart+thumbHeight {
			lines[i] = thumb.Render("┃")
		}
	}
	return strings.Join(lines, "\n")
}

func (m sandboxTUIModel) dialogContent(theme tuiTheme, kind tuiDialog, innerWidth int) (string, color.Color) {
	border := theme.accent
	content := ""
	switch kind {
	case tuiHelpDialog:
		content = m.renderHelpDialog(theme, innerWidth)
	case tuiInfoDialog:
		content = m.renderInfoDialog(theme, innerWidth)
	case tuiPacketDetailDialog:
		content = m.renderPacketDetailDialog(theme, innerWidth)
	case tuiRemoveDialog:
		content = m.renderRemoveDialog(theme, innerWidth)
		border = theme.error
	case tuiShareRemoveDialog:
		content = m.renderShareRemoveDialog(theme, innerWidth)
		border = theme.error
	case tuiCreateDialog:
		content = m.renderCreateDialog(theme, innerWidth)
	case tuiEditDialog:
		content = m.renderEditDialog(theme, innerWidth)
	case tuiShareAddDialog:
		content = m.renderShareAddDialog(theme, innerWidth)
	case tuiPortUnpublishDialog:
		content = m.renderPortUnpublishDialog(theme, innerWidth)
		border = theme.error
	case tuiPortPublishDialog:
		content = m.renderPortPublishDialog(theme, innerWidth)
	case tuiNetworkPolicyDialog:
		content = m.renderNetworkPolicyDialog(theme, innerWidth)
	case tuiRuleAddDialog:
		content = m.renderRuleAddDialog(theme, innerWidth)
	case tuiRuleRemoveDialog:
		content = m.renderRuleRemoveDialog(theme, innerWidth)
		border = theme.error
	case tuiSecretAddDialog:
		content = m.renderSecretAddDialog(theme, innerWidth)
	case tuiSecretRemoveDialog:
		content = m.renderSecretRemoveDialog(theme, innerWidth)
		border = theme.error
	case tuiMCPRemoteDialog:
		content = m.renderMCPRemoteDialog(theme, innerWidth)
	case tuiMCPFilesystemDialog:
		content = m.renderMCPFilesystemDialog(theme, innerWidth)
	case tuiMCPRemoveDialog:
		content = m.renderMCPRemoveDialog(theme, innerWidth)
		border = theme.error
	case tuiUpdateDialog:
		content = m.renderUpdateDialog(theme, innerWidth)
		border = theme.warning
	case tuiImagePullDialog:
		content = m.renderImagePullDialog(theme, innerWidth)
	case tuiImageRemoveDialog:
		content = m.renderImageRemoveDialog(theme, innerWidth)
		border = theme.error
	case tuiImagePruneDialog:
		content = m.renderImagePruneDialog(theme, innerWidth)
		border = theme.warning
	case tuiRegistryLoginDialog:
		content = m.renderRegistryLoginDialog(theme, innerWidth)
	case tuiRegistryLogoutDialog:
		content = m.renderRegistryLogoutDialog(theme, innerWidth)
		border = theme.error
	}
	return content, border
}

func (m sandboxTUIModel) dialogHeader(theme tuiTheme, title string, width int) string {
	left := lipgloss.NewStyle().Bold(true).Foreground(theme.text).Render(title)
	right := lipgloss.NewStyle().Foreground(theme.muted).Render("esc  ×")
	return joinSides(left, right, width) + "\n" +
		lipgloss.NewStyle().Foreground(theme.borderMuted).Render(strings.Repeat("─", width))
}

func (m sandboxTUIModel) renderHelpDialog(theme tuiTheme, width int) string {
	header := m.dialogHeader(theme, "Keyboard shortcuts", width)
	column := func(title string, rows [][2]string) string {
		lines := []string{lipgloss.NewStyle().Bold(true).Foreground(theme.accent).Render(title)}
		for _, row := range rows {
			key := lipgloss.NewStyle().Bold(true).Foreground(theme.text).Width(13).Render(row[0])
			desc := lipgloss.NewStyle().Foreground(theme.secondary).Render(row[1])
			lines = append(lines, key+" "+desc)
		}
		return strings.Join(lines, "\n")
	}
	navigation := column("NAVIGATION", [][2]string{
		{"←↑↓→ / hjkl", "move selection"},
		{"pgup / pgdown", "move one page"},
		{"g / G", "first / last row"},
		{"mouse wheel", "scroll the view"},
		{"tab / S-tab", "switch views"},
		{"0 … 9", "jump to overview or a view"},
	})
	actions := column("SANDBOX ACTIONS", [][2]string{
		{"enter", "open or start"},
		{"s", "start / stop"},
		{"n", "create a sandbox"},
		{"e", "edit resources / isolation"},
		{"i", "show details"},
		{"d", "remove"},
		{"r", "refresh"},
	})
	viewActions := column("VIEW ACTIONS", [][2]string{
		{"a", "add a host share"},
		{"d", "remove selected share"},
		{"r", "replace selected share"},
		{"e (Rules)", "edit network policy"},
		{"space (Pkts)", "pause packet display"},
		{"c (Packets)", "clear packet capture"},
		{"d (Packets)", "inspect packet contents"},
		{"a/f/e/d MCP", "remote add, filesystem, edit, remove"},
		{"p/d/u (Images)", "pull, remove, prune"},
		{"a/d + s (Images)", "registry login/logout, section"},
	})
	applicationRows := [][2]string{
		{"?", "toggle this help"},
		{"q / ctrl+c", "quit"},
		{"ctrl+c / ctrl+v", "copy / paste focused field"},
		{"click", "select a navigation item, row, card, or visible action"},
		{"double-click", "inspect, open, or start"},
	}
	if m.updateStatus.Available {
		applicationRows = append([][2]string{{"U", "install " + m.updateStatus.Latest}}, applicationRows...)
	}
	application := column("APPLICATION", applicationRows)
	var body string
	if width >= 58 {
		body = lipgloss.JoinHorizontal(lipgloss.Top, navigation, strings.Repeat(" ", 3), actions, strings.Repeat(" ", 3), viewActions)
		body += "\n\n" + application
	} else {
		binding := func(key, description string) string {
			return lipgloss.NewStyle().Bold(true).Foreground(theme.text).Render(key) + " " +
				lipgloss.NewStyle().Foreground(theme.secondary).Render(description)
		}
		navigation = strings.Join([]string{
			lipgloss.NewStyle().Bold(true).Foreground(theme.accent).Render("NAVIGATION"),
			binding("←↑↓→ / hjkl", "move") + "  ·  " + binding("tab", "view") + "  ·  " + binding("1…9", "jump"),
			binding("g / G", "first / last") + "  ·  " + binding("wheel", "scroll"),
		}, "\n")
		actions = strings.Join([]string{
			lipgloss.NewStyle().Bold(true).Foreground(theme.accent).Render("SANDBOX ACTIONS"),
			binding("enter", "open / start") + "  ·  " + binding("s", "start / stop"),
			binding("n", "create") + "  ·  " + binding("i", "details") + "  ·  " + binding("d", "remove"),
			binding("r", "refresh") + "  ·  " + binding("e", "policy") + "  ·  " + binding("a/d/r", "mounts"),
			binding("d/space/c", "pkts") + "  ·  " + binding("a/f/e/d", "MCP") + "  ·  " + binding("p/d/u/s", "images"),
		}, "\n")
		application = strings.Join([]string{
			lipgloss.NewStyle().Bold(true).Foreground(theme.accent).Render("APPLICATION"),
			binding("?", "help") + "  ·  " + binding("q", "quit") + "  ·  " + binding("click", "select"),
		}, "\n")
		body = navigation + "\n\n" + actions + "\n\n" + application
	}
	return header + "\n\n" + body
}

func (m sandboxTUIModel) renderInfoDialog(theme tuiTheme, width int) string {
	header := m.dialogHeader(theme, "Sandbox details", width)
	sandbox := m.selected()
	if sandbox == nil {
		return header + "\n\n" + lipgloss.NewStyle().Foreground(theme.muted).Render("No sandbox selected.")
	}
	state := m.renderSandboxState(theme, *sandbox)
	rows := [][2]string{
		{"State", state},
		{"Image", sandbox.Image},
		{"Runtime", sandbox.Runtime},
		{"Kernel", pathBaseOr(sandbox.Kernel, "unknown")},
		{"Compute", fmt.Sprintf("%d CPU · %d MiB RAM", maxInt(1, sandbox.VCPUs), sandbox.MemMB)},
		{"Isolation", defaultText(sandbox.ProcessIsolation, "auto")},
		{"SSH", map[bool]string{true: "enabled", false: "disabled"}[sandbox.SSH]},
		{"Dev Containers", map[bool]string{true: "enabled", false: "disabled"}[sandbox.DevContainers]},
		{"Storage", sandboxStorageSummary(*sandbox, true)},
		{"Network", map[bool]string{true: "enabled", false: "disabled"}[sandbox.Net]},
	}
	if sandbox.Net {
		rows = append(rows,
			[2]string{"Local access", map[bool]string{true: "allowed", false: "blocked"}[sandbox.AllowLocal]},
			[2]string{"Policy", pathBaseOr(sandbox.NetPolicy, "built-in default")},
		)
		if sandbox.Proxy != "" {
			mode := "environment routing"
			if sandbox.ProxyEnforce {
				mode = "direct web egress blocked"
			}
			rows = append(rows,
				[2]string{"Proxy", sandbox.Proxy},
				[2]string{"Proxy mode", mode},
			)
			if sandbox.NoProxy != "" {
				rows = append(rows, [2]string{"No proxy", sandbox.NoProxy})
			}
		}
	}
	rows = append(rows,
		[2]string{"Traffic", "↑ " + formatBytes(sandbox.TXBytes) + "  ↓ " + formatBytes(sandbox.RXBytes)},
		[2]string{"Blocked", fmt.Sprintf("%d packets", sandbox.DroppedPackets)},
		[2]string{"Shares", fmt.Sprintf("%d", sandbox.Shares)},
		[2]string{"Published", fmt.Sprintf("%d ports", sandbox.Ports)},
		[2]string{"Secrets", sandbox.Secrets},
	)
	if sandbox.PID > 0 {
		rows = append(rows, [2]string{"VMM PID", fmt.Sprint(sandbox.PID)})
	}
	var lines []string
	for _, row := range rows {
		label := lipgloss.NewStyle().Foreground(theme.muted).Width(12).Render(row[0])
		value := row[1]
		if !strings.Contains(value, "\x1b[") {
			value = truncateText(value, maxInt(4, width-12))
		}
		lines = append(lines, label+value)
	}
	var paths []string
	appendPath := func(label, path string) {
		if path == "" {
			return
		}
		paths = append(paths, lipgloss.NewStyle().Foreground(theme.muted).Render(label)+"\n"+lipgloss.Wrap(path, width, ""))
	}
	appendPath("Kernel asset", sandbox.Kernel)
	appendPath("Disk image", sandbox.RWLayer)
	appendPath("Policy file", sandbox.NetPolicy)
	appendPath("Config", sandbox.ConfigPath)
	footer := lipgloss.NewStyle().Foreground(theme.muted).Render("c copy all  •  i / esc close")
	return header + "\n\n" + strings.Join(lines, "\n") + "\n\n" + strings.Join(paths, "\n\n") + "\n\n" + footer
}

func sandboxStorageSummary(sandbox tuiSandbox, details bool) string {
	if sandbox.RWLayer == "" {
		if sandbox.RW {
			return "writable overlay"
		}
		return "read-only root filesystem"
	}
	mode := "read-only"
	if sandbox.RW {
		mode = "writable"
	}
	if sandbox.DiskSizeMiB == 0 {
		return mode + " persistent disk"
	}
	size := formatDiskSizeMiB(sandbox.DiskSizeMiB, details)
	if details {
		return size + " persistent ext4 · " + mode
	}
	return size + " persistent · " + mode
}

func formatDiskSizeMiB(size uint, details bool) string {
	unitMiB, unitGiB := "MB", "GB"
	if details {
		unitMiB, unitGiB = "MiB", "GiB"
	}
	if size >= 1024 && size%1024 == 0 {
		return fmt.Sprintf("%d%s", size/1024, unitGiB)
	}
	return fmt.Sprintf("%d%s", size, unitMiB)
}

func pathBaseOr(path, fallback string) string {
	if path == "" {
		return fallback
	}
	return filepath.Base(path)
}

func (m sandboxTUIModel) renderRemoveDialog(theme tuiTheme, width int) string {
	header := m.dialogHeader(theme, "Remove Sandbox", width)
	name := ""
	if selected := m.selected(); selected != nil {
		name = selected.Name
	}
	label := lipgloss.NewStyle().Foreground(theme.secondary).Render("Sandbox: ")
	value := lipgloss.NewStyle().Bold(true).Foreground(theme.text).Render(name)
	warning := lipgloss.NewStyle().Foreground(theme.error).Render("This cannot be undone.")
	question := lipgloss.NewStyle().Bold(true).Foreground(theme.text).Render(fmt.Sprintf("Remove %q?", name))
	cancel := renderDialogButton(theme, "Cancel", !m.confirmRemove, false)
	remove := renderDialogButton(theme, "Remove", m.confirmRemove, true)
	buttons := alignRight(cancel+"  "+remove, width)
	hint := lipgloss.NewStyle().Foreground(theme.muted).Render("←/→ choose  •  enter confirm")
	return header + "\n\n" + label + value + "\n\n" + warning + "\n\n" + question + "\n\n" + renderConfirmationFooter(buttons, hint)
}

func (m sandboxTUIModel) renderUpdateDialog(theme tuiTheme, width int) string {
	header := m.dialogHeader(theme, "Update Gantry", width)
	current := lipgloss.NewStyle().Foreground(theme.secondary).Render("Current:   ") +
		lipgloss.NewStyle().Bold(true).Foreground(theme.text).Render(defaultText(m.updateStatus.Current, "unknown"))
	latest := lipgloss.NewStyle().Foreground(theme.secondary).Render("Available: ") +
		lipgloss.NewStyle().Bold(true).Foreground(theme.warning).Render(defaultText(m.updateStatus.Latest, "unknown"))
	description := lipgloss.NewStyle().Foreground(theme.secondary).Render(
		lipgloss.Wrap("Download the platform binary, verify its SHA-256 release sidecar, and replace Gantry in place.", width, ""),
	)
	note := lipgloss.NewStyle().Foreground(theme.muted).Render("The dashboard closes after a successful update; running sandboxes keep running.")
	cancel := renderDialogButton(theme, "Cancel", !m.confirmRemove, false)
	update := renderDialogButton(theme, "Update", m.confirmRemove, false)
	buttons := alignRight(cancel+"  "+update, width)
	hint := lipgloss.NewStyle().Foreground(theme.muted).Render("←/→ choose  •  enter confirm")
	return header + "\n\n" + current + "\n" + latest + "\n\n" + description + "\n\n" + note + "\n\n" + renderConfirmationFooter(buttons, hint)
}

func (m sandboxTUIModel) renderCreateDialog(theme tuiTheme, width int) string {
	header := m.dialogHeader(theme, "Create sandbox", width)
	description := lipgloss.NewStyle().Foreground(theme.secondary).Render("Create and boot a persistent local microVM.")
	section := func(title string) string {
		return lipgloss.NewStyle().Bold(true).Foreground(theme.accent).Render(strings.ToUpper(title))
	}
	nameLabel := formLabel(theme, "Name", m.createFocus == 0)
	imageLabel := formLabel(theme, "OCI image", m.createFocus == 1) + lipgloss.NewStyle().Foreground(theme.muted).Render("  optional")
	nameField := renderInputField(theme, m.createName.View(), width, m.createFocus == 0)
	imageField := renderInputField(theme, m.createImage.View(), width, m.createFocus == 1)
	runtimeLabel := formLabel(theme, "Runtime", m.createFocus == 2)
	runtimeValue := lipgloss.NewStyle().Bold(m.createFocus == 2).Foreground(theme.text).Render(m.createRuntime) +
		lipgloss.NewStyle().Foreground(theme.muted).Render("  ←/→ or space to change")
	kernelLabel := formLabel(theme, "Kernel", m.createFocus == 3)
	kernelValue := lipgloss.NewStyle().Bold(m.createFocus == 3).Foreground(theme.text).Render(truncateText(m.createKernelLabel(), maxInt(12, width-16))) +
		lipgloss.NewStyle().Foreground(theme.muted).Render("  ←/→ to change")
	sshLabel := formLabel(theme, "SSH", m.createFocus == 4)
	sshValue := renderFeatureToggle(theme, m.createSSH)
	devLabel := formLabel(theme, "Dev Containers", m.createFocus == 5)
	devValue := renderFeatureToggle(theme, m.createDevContainers)
	developmentNote := "Adds the curated IDE environment and nested Podman."
	if m.createDevContainers {
		developmentNote = fmt.Sprintf("SSH and crun enabled automatically · IDE disk follows Persistent disk (%s)", formatMiBHuman(uint(m.createDisk.Value)))
	}
	developmentHint := lipgloss.NewStyle().Foreground(theme.muted).Render(developmentNote)
	cpuLabel := formLabel(theme, "CPUs", m.createFocus == 6)
	cpuSlider := m.createCPUs.View(theme, width, m.createFocus == 6, "CPU")
	memoryLabel := formLabel(theme, "Memory", m.createFocus == 7)
	memorySlider := m.createMemory.View(theme, width, m.createFocus == 7, "MiB")
	diskLabel := formLabel(theme, "Persistent disk", m.createFocus == 8)
	diskSlider := m.createDisk.View(theme, width, m.createFocus == 8, "MiB")
	isolationLabel := formLabel(theme, "Process isolation", m.createFocus == 9)
	isolationValue := lipgloss.NewStyle().Bold(m.createFocus == 9).Foreground(theme.text).Render(m.createIsolation) +
		lipgloss.NewStyle().Foreground(theme.muted).Render("  ←/→ cycles auto / required / off")

	fields := []string{
		nameLabel + "\n" + nameField,
		imageLabel + "\n" + imageField,
		runtimeLabel + "\n" + runtimeValue,
		kernelLabel + "\n" + kernelValue,
		sshLabel + "\n" + sshValue,
		devLabel + "\n" + devValue,
		cpuLabel + "\n" + cpuSlider,
		memoryLabel + "\n" + memorySlider,
		diskLabel + "\n" + diskSlider,
		isolationLabel + "\n" + isolationValue,
	}
	if m.formError != "" && m.createErrFocus >= 0 && m.createErrFocus < len(fields) {
		errorLine := lipgloss.NewStyle().Foreground(theme.error).Render(lipgloss.Wrap(safeUIBlock(m.formError), width, ""))
		fields[m.createErrFocus] += "\n" + errorLine
	}

	cancel := renderDialogButton(theme, "Cancel", false, false)
	create := renderDialogButton(theme, "Create sandbox", m.createFocus == 10, false)
	buttons := alignRight(cancel+"  "+create, width)
	hint := lipgloss.NewStyle().Foreground(theme.muted).Render("tab next  •  ←/→ change  •  ctrl+enter create  •  esc cancel")
	gap := m.formSectionGap()
	groups := []string{
		section("Identity") + gap + strings.Join(fields[0:2], gap),
		section("Runtime") + gap + strings.Join(fields[2:4], gap),
		section("Development") + gap + strings.Join(fields[4:6], gap) + "\n" + developmentHint,
		section("Resources") + gap + strings.Join(fields[6:9], gap),
		section("Security") + gap + fields[9],
	}
	return header + "\n" + description + gap + strings.Join(groups, gap) + "\n" + renderFormFooter("", buttons, hint)
}

func (m sandboxTUIModel) renderEditDialog(theme tuiTheme, width int) string {
	header := m.dialogHeader(theme, "Edit Sandbox", width)
	sandbox := m.selected()
	if sandbox == nil {
		return header + "\n\n" + lipgloss.NewStyle().Foreground(theme.muted).Render("No sandbox selected.")
	}
	description := lipgloss.NewStyle().Foreground(theme.secondary).Render(truncateText("Change live capabilities and the next VM allocation for "+sandbox.Name+".", width))
	sshLabel := formLabel(theme, "SSH", m.editFocus == 0)
	sshValue := renderFeatureToggle(theme, m.editSSH)
	devLabel := formLabel(theme, "Dev Containers", m.editFocus == 1)
	devValue := renderFeatureToggle(theme, m.editDevContainers)
	cpuLabel := formLabel(theme, "CPUs", m.editFocus == 2)
	cpuSlider := m.editCPUs.View(theme, width, m.editFocus == 2, "CPU")
	memoryLabel := formLabel(theme, "Memory", m.editFocus == 3)
	memorySlider := m.editMemory.View(theme, width, m.editFocus == 3, "MiB")
	isolationLabel := formLabel(theme, "Process isolation", m.editFocus == 4)
	isolationValue := lipgloss.NewStyle().Foreground(theme.text).Render(m.editIsolation) +
		lipgloss.NewStyle().Foreground(theme.muted).Render("  (space cycles auto/required/off)")
	note := "Applied when the sandbox next starts."
	if sandbox.State == tuiRunning {
		note = "SSH applies live; restart to apply Dev Containers or allocation changes."
	}
	noteLine := lipgloss.NewStyle().Foreground(theme.warning).Render(truncateText(note, width))
	errorLine := ""
	if m.formError != "" {
		errorLine = lipgloss.NewStyle().Foreground(theme.error).Render(truncateText(m.formError, width))
	}
	save := renderDialogButton(theme, "Save", m.editFocus == 5, false)
	buttons := alignRight(save, width)
	hint := lipgloss.NewStyle().Foreground(theme.muted).Render(truncateText("←/→ adjust  •  PgUp/PgDn jump  •  tab next  •  esc cancel", width))
	return header + "\n" + description + "\n\n" + sshLabel + "\n" + sshValue + "\n\n" + devLabel + "\n" + devValue + "\n\n" + cpuLabel + "\n" + cpuSlider + "\n\n" + memoryLabel + "\n" + memorySlider + "\n\n" + isolationLabel + "\n" + isolationValue + "\n\n" + noteLine + "\n" + renderFormFooter(errorLine, buttons, hint)
}

func renderFeatureToggle(theme tuiTheme, enabled bool) string {
	box, value := "[ ]", "Disabled"
	foreground := theme.secondary
	if enabled {
		box, value = "[✓]", "Enabled"
		foreground = theme.success
	}
	return lipgloss.NewStyle().Bold(true).Foreground(foreground).Render(box+" "+value) +
		lipgloss.NewStyle().Foreground(theme.muted).Render("  space toggles")
}

func (m sandboxTUIModel) renderShareRemoveDialog(theme tuiTheme, width int) string {
	header := m.dialogHeader(theme, "Remove Share", width)
	row := m.selectedMount()
	if row == nil {
		return header + "\n\n" + lipgloss.NewStyle().Foreground(theme.muted).Render("No share selected.")
	}
	label := lipgloss.NewStyle().Foreground(theme.secondary).Render("Share: ")
	value := lipgloss.NewStyle().Bold(true).Foreground(theme.text).Render(row.Sandbox + " / " + row.Tag)
	path := lipgloss.NewStyle().Foreground(theme.muted).Render(truncateText(row.Host, width))
	warningText := "Existing processes using the share may lose access."
	if sandbox := m.sandboxNamed(row.Sandbox); sandbox != nil && sandbox.State == tuiStopped {
		warningText = "This share will no longer be attached on the next start."
	}
	warning := lipgloss.NewStyle().Foreground(theme.error).Render(warningText)
	question := lipgloss.NewStyle().Bold(true).Foreground(theme.text).Render(fmt.Sprintf("Remove %q?", row.Tag))
	cancel := renderDialogButton(theme, "Cancel", !m.confirmRemove, false)
	remove := renderDialogButton(theme, "Remove", m.confirmRemove, true)
	buttons := alignRight(cancel+"  "+remove, width)
	hint := lipgloss.NewStyle().Foreground(theme.muted).Render("←/→ choose  •  enter confirm")
	return header + "\n\n" + label + value + "\n" + path + "\n\n" + warning + "\n\n" + question + "\n\n" + renderConfirmationFooter(buttons, hint)
}

func (m sandboxTUIModel) renderShareAddDialog(theme tuiTheme, width int) string {
	title, description, buttonLabel := m.shareDialogCopy()
	header := m.dialogHeader(theme, title, width)
	sandboxLabel := formLabel(theme, "Sandbox", m.shareFocus == 0)
	sandboxField := m.shareSandbox.View(theme, width, m.shareFocus == 0)
	tagLabel := formLabel(theme, "Tag", m.shareFocus == 1)
	pathLabel := formLabel(theme, "Host path", m.shareFocus == 2)
	mountLabel := formLabel(theme, "Mount point", m.shareFocus == 3)
	ownerLabel := formLabel(theme, "Guest owner", m.shareFocus == 4)
	tagField := renderInputField(theme, m.shareTag.View(), width, m.shareFocus == 1)
	pathField := renderInputField(theme, m.sharePath.View(), width, m.shareFocus == 2)
	mountField := renderInputField(theme, m.shareMount.View(), width, m.shareFocus == 3)
	ownerField := renderInputField(theme, m.shareOwner.View(), width, m.shareFocus == 4)
	mode := "read-write"
	if m.shareRO {
		mode = "read-only"
	}
	modeLabel := formLabel(theme, "Mode", m.shareFocus == 5)
	modeValue := lipgloss.NewStyle().Foreground(theme.text).Render(mode) +
		lipgloss.NewStyle().Foreground(theme.muted).Render("  (space toggles)")
	errorLine := ""
	if m.formError != "" {
		errorLine = lipgloss.NewStyle().Foreground(theme.error).Render(truncateText(m.formError, width))
	}
	button := renderDialogButton(theme, buttonLabel, m.shareFocus == 6, false)
	buttons := alignRight(button, width)
	hint := lipgloss.NewStyle().Foreground(theme.muted).Render("tab next  •  enter continue  •  esc cancel")
	gap := m.formSectionGap()
	fields := []string{
		sandboxLabel + "\n" + sandboxField,
		tagLabel + "\n" + tagField,
		pathLabel + "\n" + pathField,
		mountLabel + "\n" + mountField,
		ownerLabel + "\n" + ownerField,
		modeLabel + "  " + modeValue,
	}
	return header + "\n" + lipgloss.NewStyle().Foreground(theme.secondary).Render(description) +
		gap + strings.Join(fields, gap) + "\n" + renderFormFooter(errorLine, buttons, hint)
}

func (m sandboxTUIModel) shareDialogCopy() (title, description, button string) {
	target := m.sandboxNamed(m.shareSandbox.Value())
	running := target == nil || target.State == tuiRunning
	live := running
	title = "Add Live Share"
	description = "Attach a host directory without restarting the sandbox."
	button = "Add"
	if !live {
		title = "Add Share"
		description = "Save this share; restart the sandbox to attach it."
		button = "Save"
		if !running {
			description = "Save this share; it will be attached when the sandbox next starts."
		}
	}
	tag := strings.TrimSpace(m.shareTag.Value())
	mountpoint := strings.TrimSpace(m.shareMount.Value())
	customMount := mountpoint != "" && mountpoint != m.service.DefaultShareMount(tag)
	if customMount && live {
		title = "Add Share"
		description = "Save this container mount point; restart the sandbox to apply it."
		button = "Save"
	}
	if m.shareReplace {
		title = "Replace Share"
		description = "Replace the selected share while the sandbox keeps running."
		button = "Replace"
		if !live {
			description = "Save this replacement; restart the sandbox to apply it."
			button = "Save"
			if !running {
				description = "Save this replacement; it will apply when the sandbox next starts."
			}
		} else if customMount {
			description = "Save this container mount point; restart the sandbox to apply it."
			button = "Save"
		}
	}
	return title, description, button
}

func (m sandboxTUIModel) renderPortUnpublishDialog(theme tuiTheme, width int) string {
	header := m.dialogHeader(theme, "Unpublish Port", width)
	row := m.selectedPort()
	if row == nil {
		return header + "\n\n" + lipgloss.NewStyle().Foreground(theme.muted).Render("No port selected.")
	}
	label := lipgloss.NewStyle().Foreground(theme.secondary).Render("Publish: ")
	value := lipgloss.NewStyle().Bold(true).Foreground(theme.text).Render(fmt.Sprintf("%s  %s → %d/%s", row.Sandbox, row.Bind, row.Guest, row.Proto))
	warning := lipgloss.NewStyle().Foreground(theme.error).Render(row.Bind + " will stop forwarding into the sandbox.")
	question := lipgloss.NewStyle().Bold(true).Foreground(theme.text).Render(fmt.Sprintf("Unpublish %s?", row.Bind))
	cancel := renderDialogButton(theme, "Cancel", !m.confirmRemove, false)
	remove := renderDialogButton(theme, "Unpublish", m.confirmRemove, true)
	buttons := alignRight(cancel+"  "+remove, width)
	hint := lipgloss.NewStyle().Foreground(theme.muted).Render("←/→ choose  •  enter confirm")
	return header + "\n\n" + label + value + "\n\n" + warning + "\n\n" + question + "\n\n" + renderConfirmationFooter(buttons, hint)
}

func (m sandboxTUIModel) renderPortPublishDialog(theme tuiTheme, width int) string {
	header := m.dialogHeader(theme, "Publish Port", width)
	description := "Forward a guest port to a host listener, without a restart."
	sandboxLabel := formLabel(theme, "Sandbox", m.portFocus == 0)
	sandboxField := m.portSandbox.View(theme, width, m.portFocus == 0)
	bindLabel := formLabel(theme, "Host bind", m.portFocus == 1)
	guestLabel := formLabel(theme, "Guest port", m.portFocus == 2)
	bindField := renderInputField(theme, m.portBind.View(), width, m.portFocus == 1)
	guestField := renderInputField(theme, m.portGuest.View(), width, m.portFocus == 2)
	proto := "tcp"
	if m.portUDP {
		proto = "udp"
	}
	protoLabel := formLabel(theme, "Protocol", m.portFocus == 3)
	protoValue := lipgloss.NewStyle().Foreground(theme.text).Render(proto) +
		lipgloss.NewStyle().Foreground(theme.muted).Render("  (space toggles)")
	// Wrap before the outer dialog applies its width. Otherwise the surface
	// wraps this line after content truncation and pushes the footer/border out
	// of the declared modal bounds.
	exposure := lipgloss.NewStyle().Foreground(theme.muted).Render(
		lipgloss.Wrap("Bind is loopback by default; write 0.0.0.0:port to expose on the LAN.", width, ""),
	)
	errorLine := ""
	if m.formError != "" {
		errorLine = lipgloss.NewStyle().Foreground(theme.error).Render(truncateText(m.formError, width))
	}
	button := renderDialogButton(theme, "Publish", m.portFocus == 4, false)
	buttons := alignRight(button, width)
	hint := lipgloss.NewStyle().Foreground(theme.muted).Render("tab next  •  enter continue  •  esc cancel")
	gap := m.formSectionGap()
	fields := []string{
		sandboxLabel + "\n" + sandboxField,
		bindLabel + "\n" + bindField,
		guestLabel + "\n" + guestField,
		protoLabel + "  " + protoValue + "\n" + exposure,
	}
	return header + "\n" + lipgloss.NewStyle().Foreground(theme.secondary).Render(description) +
		gap + strings.Join(fields, gap) + "\n" + renderFormFooter(errorLine, buttons, hint)
}

func (m sandboxTUIModel) renderNetworkPolicyDialog(theme tuiTheme, width int) string {
	header := m.dialogHeader(theme, "Network Policy", width)
	description := lipgloss.NewStyle().Foreground(theme.secondary).Render("Replace the running sandbox's egress policy immediately.")
	sandboxLabel := formLabel(theme, "Sandbox", m.policyFocus == 0)
	sandboxField := m.policySandbox.View(theme, width, m.policyFocus == 0)
	pathLabel := formLabel(theme, "Policy file", m.policyFocus == 1) +
		lipgloss.NewStyle().Foreground(theme.muted).Render("  blank = built-in default")
	pathField := renderInputField(theme, m.policyPath.View(), width, m.policyFocus == 1)
	localLabel := formLabel(theme, "Local network override", m.policyFocus == 2)
	localValue := "blocked"
	if m.policyLocal {
		localValue = "allowed"
	}
	local := localLabel + "  " + lipgloss.NewStyle().Foreground(theme.text).Render(localValue) +
		lipgloss.NewStyle().Foreground(theme.muted).Render("  (space toggles)")
	note := lipgloss.NewStyle().Foreground(theme.warning).Render("Subsequent packets use this policy immediately; existing sockets are not actively closed.")
	errorLine := ""
	if m.formError != "" {
		errorLine = lipgloss.NewStyle().Foreground(theme.error).Render(truncateText(m.formError, width))
	}
	apply := renderDialogButton(theme, "Apply", m.policyFocus == 3, false)
	buttons := alignRight(apply, width)
	hint := lipgloss.NewStyle().Foreground(theme.muted).Render("tab next  •  enter continue  •  esc cancel")
	gap := m.formSectionGap()
	fields := []string{
		sandboxLabel + "\n" + sandboxField,
		pathLabel + "\n" + pathField,
		local,
		note,
	}
	return header + "\n" + description + gap + strings.Join(fields, gap) + "\n" + renderFormFooter(errorLine, buttons, hint)
}

func (m sandboxTUIModel) renderRuleAddDialog(theme tuiTheme, width int) string {
	domainRule := m.ruleProtocol == "dns"
	title := "Traffic Rule"
	descriptionText := "Add a highest-priority rule for the selected observed connection."
	if domainRule {
		title = "DNS Allowlist"
		descriptionText = "Add the queried domain to allowDomains for this sandbox."
	}
	header := m.dialogHeader(theme, title, width)
	description := lipgloss.NewStyle().Foreground(theme.secondary).Render(descriptionText)
	sandboxLabel := formLabel(theme, "Sandbox", m.ruleFocus == 0)
	sandboxField := m.ruleSandbox.View(theme, width, m.ruleFocus == 0)
	actionLabel := formLabel(theme, "Decision", m.ruleFocus == 1)
	actionColor := theme.error
	if m.ruleAction == "allow" {
		actionColor = theme.success
	}
	actionHint := "  (space toggles)"
	if domainRule {
		actionHint = "  (domain allowlist)"
	}
	action := actionLabel + "  " + lipgloss.NewStyle().Bold(true).Foreground(actionColor).Render(m.ruleAction) +
		lipgloss.NewStyle().Foreground(theme.muted).Render(actionHint)
	targetName := "Destination"
	if domainRule {
		targetName = "Domain"
	}
	targetLabel := formLabel(theme, targetName, m.ruleFocus == 2)
	targetField := renderInputField(theme, m.ruleTarget.View(), width, m.ruleFocus == 2)
	protoLabel := formLabel(theme, "Protocol", m.ruleFocus == 3)
	protoHint := "  (space cycles any/TCP/UDP/ICMP)"
	if domainRule {
		protoHint = "  (queried hostname)"
	}
	proto := protoLabel + "  " + lipgloss.NewStyle().Foreground(theme.text).Render(strings.ToUpper(m.ruleProtocol)) +
		lipgloss.NewStyle().Foreground(theme.muted).Render(protoHint)
	portsLabel := formLabel(theme, "Destination ports", m.ruleFocus == 4) +
		lipgloss.NewStyle().Foreground(theme.muted).Render("  TCP/UDP only")
	portsField := renderInputField(theme, m.rulePorts.View(), width, m.ruleFocus == 4)
	if domainRule {
		portsLabel = formLabel(theme, "Destination ports", false)
		portsField = lipgloss.NewStyle().Foreground(theme.muted).Render("not used for DNS allowlists")
	}
	errorLine := ""
	if m.formError != "" {
		errorLine = lipgloss.NewStyle().Foreground(theme.error).Render(truncateText(m.formError, width))
	}
	button := renderDialogButton(theme, m.ruleAddButtonLabel(), m.ruleFocus == 5, false)
	buttons := alignRight(button, width)
	hintText := "tab next  •  space toggle  •  enter continue  •  esc cancel"
	if domainRule {
		hintText = "tab next  •  enter continue  •  esc cancel"
	}
	hint := lipgloss.NewStyle().Foreground(theme.muted).Render(hintText)
	gap := m.formSectionGap()
	fields := []string{
		sandboxLabel + "\n" + sandboxField,
		action,
		targetLabel + "\n" + targetField,
		proto,
		portsLabel + "\n" + portsField,
	}
	return header + "\n" + description + gap + strings.Join(fields, gap) + "\n" + renderFormFooter(errorLine, buttons, hint)
}

func (m sandboxTUIModel) renderRuleRemoveDialog(theme tuiTheme, width int) string {
	header := m.dialogHeader(theme, "Remove Network Rule", width)
	row := m.selectedRule()
	if row == nil {
		return header + "\n\n" + lipgloss.NewStyle().Foreground(theme.muted).Render("No removable policy entry selected.")
	}
	value := lipgloss.NewStyle().Bold(true).Foreground(theme.text).Render(row.Sandbox + " · " + row.Source)
	detail := lipgloss.NewStyle().Foreground(theme.secondary).Render(strings.ToUpper(row.Action) + " " + row.Target + " " + strings.ToUpper(row.Proto) + " " + defaultText(row.Ports, "any port"))
	question := lipgloss.NewStyle().Bold(true).Foreground(theme.text).Render("Remove this policy entry?")
	cancel := renderDialogButton(theme, "Cancel", !m.confirmRemove, false)
	remove := renderDialogButton(theme, "Remove", m.confirmRemove, true)
	buttons := alignRight(cancel+"  "+remove, width)
	hint := lipgloss.NewStyle().Foreground(theme.muted).Render("←/→ choose  •  enter confirm")
	return header + "\n\n" + value + "\n" + detail + "\n\n" + question + "\n\n" + renderConfirmationFooter(buttons, hint)
}

func (m sandboxTUIModel) renderSecretAddDialog(theme tuiTheme, width int) string {
	header := m.dialogHeader(theme, "Add Secret", width)
	description := lipgloss.NewStyle().Foreground(theme.secondary).Render("Load a secret into a running sandbox for future sessions.")
	sandboxLabel := formLabel(theme, "Sandbox", m.secretFocus == 0)
	sandboxField := m.secretSandbox.View(theme, width, m.secretFocus == 0)
	nameLabel := formLabel(theme, "Name", m.secretFocus == 1)
	nameField := renderInputField(theme, m.secretName.View(), width, m.secretFocus == 1)
	valueLabel := formLabel(theme, "Value", m.secretFocus == 2) + lipgloss.NewStyle().Foreground(theme.muted).Render("  write-only")
	valueField := renderInputField(theme, m.secretValue.View(), width, m.secretFocus == 2)
	note := lipgloss.NewStyle().Foreground(theme.warning).Render("Memory-only. Export the same name before restarting this sandbox.")
	errorLine := ""
	if m.formError != "" {
		errorLine = lipgloss.NewStyle().Foreground(theme.error).Render(truncateText(m.formError, width))
	}
	button := renderDialogButton(theme, "Add secret", m.secretFocus == 3, false)
	buttons := alignRight(button, width)
	hint := lipgloss.NewStyle().Foreground(theme.muted).Render("tab next  •  enter continue  •  esc cancel")
	gap := m.formSectionGap()
	fields := []string{sandboxLabel + "\n" + sandboxField, nameLabel + "\n" + nameField, valueLabel + "\n" + valueField, note}
	return header + "\n" + description + gap + strings.Join(fields, gap) + "\n" + renderFormFooter(errorLine, buttons, hint)
}

func (m sandboxTUIModel) renderSecretRemoveDialog(theme tuiTheme, width int) string {
	header := m.dialogHeader(theme, "Delete Secret", width)
	row := m.selectedSecret()
	if row == nil {
		return header + "\n\n" + lipgloss.NewStyle().Foreground(theme.muted).Render("No secret selected.")
	}
	value := lipgloss.NewStyle().Bold(true).Foreground(theme.text).Render(row.Sandbox + " / " + row.Name)
	warning := lipgloss.NewStyle().Foreground(theme.error).Render("Future sessions will no longer receive this secret.")
	question := lipgloss.NewStyle().Bold(true).Foreground(theme.text).Render("Delete this secret?")
	cancel := renderDialogButton(theme, "Cancel", !m.confirmRemove, false)
	remove := renderDialogButton(theme, "Delete", m.confirmRemove, true)
	buttons := alignRight(cancel+"  "+remove, width)
	hint := lipgloss.NewStyle().Foreground(theme.muted).Render("←/→ choose  •  enter confirm")
	return header + "\n\n" + value + "\n\n" + warning + "\n\n" + question + "\n\n" + renderConfirmationFooter(buttons, hint)
}

func renderFormFooter(errorLine, buttons, hint string) string {
	return errorLine + "\n" + buttons + "\n\n" + hint
}

func renderConfirmationFooter(buttons, hint string) string {
	return buttons + "\n\n" + hint
}

func formLabel(theme tuiTheme, label string, focused bool) string {
	color := theme.secondary
	if focused {
		color = theme.accent
	}
	return lipgloss.NewStyle().Bold(focused).Foreground(color).Render(label)
}

func renderInputField(theme tuiTheme, value string, width int, focused bool) string {
	border := theme.borderMuted
	background := theme.bg
	if focused {
		border = theme.accent
		background = theme.panelSelected
	}
	style := lipgloss.NewStyle().
		Foreground(theme.text).
		Background(background).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(border).
		Padding(0, 1).
		Width(width).
		Height(3).
		MaxHeight(3)
	return renderSurface(style, theme.text, background, value)
}

func renderDialogButton(theme tuiTheme, label string, focused, danger bool) string {
	foreground, background := theme.secondary, theme.panelRaised
	if focused {
		foreground, background = theme.accentFg, theme.accent
	}
	if danger {
		foreground = theme.error
		if focused {
			foreground, background = lipgloss.Color("#FFFFFF"), theme.error
		}
	}
	return lipgloss.NewStyle().Bold(focused).Foreground(foreground).Background(background).Padding(0, 2).Render(label)
}

func labeledValue(theme tuiTheme, label, value string, width int) string {
	labelWidth := 9
	if width < 24 {
		labelWidth = 7
	}
	left := lipgloss.NewStyle().Foreground(theme.muted).Width(labelWidth).Render(safeUILine(label))
	right := lipgloss.NewStyle().Foreground(theme.secondary).Render(truncateText(safeUILine(value), maxInt(1, width-labelWidth)))
	return truncateANSI(left+right, width)
}

func compactCardLines(lines []string, height int) []string {
	if len(lines) <= height {
		return lines
	}
	if height <= 2 {
		return lines[:height]
	}
	// Always preserve the card header and contextual action row.
	out := append([]string(nil), lines[:height-1]...)
	out = append(out, lines[len(lines)-1])
	return out
}

func busyLabel(action string) string {
	switch action {
	case "create":
		return "CREATING"
	case "start":
		return "STARTING"
	case "stop":
		return "STOPPING"
	case "delete":
		return "REMOVING"
	case "open":
		return "OPENING"
	case "update":
		return "UPDATING"
	default:
		return strings.ToUpper(action)
	}
}

func relativeUpdate(at time.Time) string {
	if at.IsZero() {
		return ""
	}
	age := time.Since(at)
	switch {
	case age < 5*time.Second:
		return "updated now"
	case age < time.Minute:
		return fmt.Sprintf("updated %ds ago", int(age.Seconds()))
	default:
		return "updated " + at.Format("15:04")
	}
}

func joinSides(left, right string, width int) string {
	if width <= 0 {
		return ""
	}
	rightWidth := lipgloss.Width(right)
	if rightWidth >= width {
		return truncateANSI(right, width)
	}
	left = truncateANSI(left, width-rightWidth-1)
	space := maxInt(1, width-lipgloss.Width(left)-rightWidth)
	return left + strings.Repeat(" ", space) + right
}

func alignRight(value string, width int) string {
	return strings.Repeat(" ", maxInt(0, width-lipgloss.Width(value))) + value
}

// renderSurface preserves a container's foreground and background after every
// nested Lip Gloss span. Nested spans emit a full SGR reset; without restoring
// the surface colors, terminals expose their default background between spans,
// producing dark rectangular patches inside cards and dialogs.
func renderSurface(style lipgloss.Style, foreground, background color.Color, content string) string {
	restore := lipgloss.NewStyle()
	if foreground != nil {
		restore = restore.Foreground(foreground)
	}
	if background != nil {
		restore = restore.Background(background)
	}
	probe := restore.Render(" ")
	marker := strings.IndexByte(probe, ' ')
	if marker > 0 {
		prefix := probe[:marker]
		content = strings.ReplaceAll(content, "\x1b[0m", "\x1b[0m"+prefix)
		content = strings.ReplaceAll(content, "\x1b[m", "\x1b[m"+prefix)
	}
	return style.Render(content)
}

func safeUILine(value string) string {
	return safeUIText(value, false)
}

func safeUIBlock(value string) string {
	return safeUIText(value, true)
}

func safeUIText(value string, multiline bool) string {
	value = ansi.Strip(strings.ReplaceAll(strings.ReplaceAll(value, "\r\n", "\n"), "\r", "\n"))
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\n' && multiline:
			return r
		case r == '\n' || r == '\t':
			return ' '
		case unicode.IsControl(r):
			return -1
		default:
			return r
		}
	}, value)
}

func truncateText(value string, width int) string {
	if width <= 0 {
		return ""
	}
	if lipgloss.Width(value) <= width {
		return value
	}
	return ansi.Truncate(value, width, "…")
}

func truncateANSI(value string, width int) string {
	if width <= 0 {
		return ""
	}
	if lipgloss.Width(value) <= width {
		return value
	}
	return ansi.Truncate(value, width, "…")
}

func sliceBlockLines(value string, start, height int) string {
	lines := strings.Split(value, "\n")
	if start <= 0 && len(lines) <= height {
		return value
	}
	start = clampInt(start, 0, len(lines))
	end := minInt(len(lines), start+maxInt(0, height))
	return strings.Join(lines[start:end], "\n")
}

func intersperse(values []string, separator string) []string {
	if len(values) < 2 {
		return values
	}
	out := make([]string, 0, len(values)*2-1)
	for i, value := range values {
		if i > 0 {
			out = append(out, separator)
		}
		out = append(out, value)
	}
	return out
}

func padLeftBlock(value string, width int) string {
	if width <= 0 {
		return value
	}
	padding := strings.Repeat(" ", width)
	lines := strings.Split(value, "\n")
	for i := range lines {
		lines[i] = padding + lines[i]
	}
	return strings.Join(lines, "\n")
}
