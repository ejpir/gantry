package dashboard

import (
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
)

type tuiHitTarget struct {
	kind   string
	action string
	page   tuiPage
	index  int
	rect   tuiRect
}

func (m sandboxTUIModel) dashboardHitTargets(layout tuiDashboardLayout) []tuiHitTarget {
	var targets []tuiHitTarget

	// Header actions use rectangles measured from the rendered menu bar.
	for action, rect := range m.menuItemRects(layout.screenWidth) {
		targets = append(targets, tuiHitTarget{kind: "menu", action: action, rect: rect})
	}

	tabs := m.tabRects(layout.screenWidth)
	for _, tab := range tabs {
		if len(tabs) == 1 {
			half := maxInt(1, tab.w/2)
			targets = append(targets,
				tuiHitTarget{kind: "cycle-page", index: -1, rect: tuiRect{x: tab.x, y: tuiTopPadding, w: half, h: 1}},
				tuiHitTarget{kind: "cycle-page", index: 1, rect: tuiRect{x: tab.x + half, y: tuiTopPadding, w: tab.w - half, h: 1}},
			)
			continue
		}
		targets = append(targets, tuiHitTarget{kind: "page", page: tab.page, rect: tuiRect{x: tab.x, y: tuiTopPadding, w: tab.w, h: 1}})
	}

	if m.busyAction != "" {
		return targets
	}
	switch m.page {
	case tuiOverviewPage:
		geometry := m.overviewGeometry(layout)
		for index, rect := range geometry.entryRects {
			targets = append(targets, tuiHitTarget{kind: "entry", index: index, rect: rect})
		}
	case tuiSandboxesPage:
		if m.usesMasterDetail(layout) {
			geometry := m.masterDetailGeometry(layout)
			for index, rect := range geometry.entryRects {
				targets = append(targets, tuiHitTarget{kind: "entry", index: index, rect: rect})
			}
			break
		}
		viewport := tuiRect{x: layout.contentX, y: layout.contentY, w: layout.width, h: layout.contentHeight}
		for index := 0; index < m.entryCount(); index++ {
			rect := layout.cardRect(index, m.scrollRow)
			visibleRect, visible := intersectRect(rect, viewport)
			if !visible {
				continue
			}
			if index < len(m.sandboxes) && index == m.cursor {
				for _, action := range sandboxCardActionRects(rect, m.sandboxes[index]) {
					if actionRect, ok := intersectRect(action.rect, viewport); ok {
						targets = append(targets, tuiHitTarget{kind: "entry-action", action: action.action, index: index, rect: actionRect})
					}
				}
			}
			targets = append(targets, tuiHitTarget{kind: "entry", index: index, rect: visibleRect})
		}
	default:
		rowY := layout.contentY + tuiTableHeaderHeight
		_, scroll, count := m.tableState()
		if scroll != nil {
			for row := 0; row < m.tableVisibleRows() && *scroll+row < count; row++ {
				targets = append(targets, tuiHitTarget{
					kind: "table-row", index: *scroll + row,
					rect: tuiRect{x: layout.contentX, y: rowY + row, w: layout.width, h: 1},
				})
			}
		}
	}
	return append(targets, m.statusBarHitTargets(layout)...)
}

func (m sandboxTUIModel) statusBarHitTargets(layout tuiDashboardLayout) []tuiHitTarget {
	if m.busyAction != "" {
		return nil
	}
	lines := strings.Split(ansi.Strip(m.renderStatusBar(tuiThemeFor(m.dark), layout.screenWidth)), "\n")
	statusY := layout.height - tuiStatusHeight
	var targets []tuiHitTarget
	for _, hint := range m.contextHints() {
		if !clickableContextKey(hint[0]) {
			continue
		}
		label := hint[0] + " " + hint[1]
		for row, line := range lines {
			if offset := strings.Index(line, label); offset >= 0 {
				x := lipgloss.Width(line[:offset])
				targets = append(targets, tuiHitTarget{kind: "shortcut", action: hint[0], rect: tuiRect{x: x, y: statusY + row, w: lipgloss.Width(label), h: 1}})
				break
			}
		}
	}
	return targets
}

func clickableContextKey(key string) bool {
	switch key {
	case "enter", "s", "e", "i", "d", "n", "?", "r", "R", "a", "p", "u", "f", "c", "t", "space", "tab", "esc":
		return true
	default:
		return false
	}
}

func (m *sandboxTUIModel) dashboardHitAt(layout tuiDashboardLayout, x, y int) (tuiHitTarget, bool) {
	targets := m.dashboardHits
	if len(targets) == 0 {
		// Unit tests and the first mouse event before an initial frame can arrive
		// without a cache. Use the same render-time builder as a safe fallback.
		targets = m.dashboardHitTargets(layout)
	}
	// Specific controls are emitted before their containing cards. Preserve
	// that precedence instead of relying on approximate horizontal segments.
	for _, target := range targets {
		if target.rect.contains(x, y) {
			return target, true
		}
	}
	return tuiHitTarget{}, false
}

func intersectRect(left, right tuiRect) (tuiRect, bool) {
	x1, y1 := maxInt(left.x, right.x), maxInt(left.y, right.y)
	x2, y2 := minInt(left.x+left.w, right.x+right.w), minInt(left.y+left.h, right.y+right.h)
	if x2 <= x1 || y2 <= y1 {
		return tuiRect{}, false
	}
	return tuiRect{x: x1, y: y1, w: x2 - x1, h: y2 - y1}, true
}

type tuiCardActionRect struct {
	action string
	rect   tuiRect
}

func sandboxCardActionRects(card tuiRect, sandbox tuiSandbox) []tuiCardActionRect {
	actions := sandboxCardActions(sandbox)
	x := card.x + 2 // border plus one cell of horizontal padding
	y := card.y + card.h - 2
	limit := card.x + card.w - 2
	result := make([]tuiCardActionRect, 0, len(actions))
	for _, action := range actions {
		width := lipgloss.Width(action.key + action.label)
		if x+width > limit {
			break
		}
		result = append(result, tuiCardActionRect{action: action.action, rect: tuiRect{x: x, y: y, w: width, h: 1}})
		x += width + 2
	}
	return result
}

func (m *sandboxTUIModel) dispatchDashboardHit(target tuiHitTarget) (tea.Model, tea.Cmd) {
	switch target.kind {
	case "menu":
		switch target.action {
		case "new":
			if m.busyAction != "" {
				return m, nil
			}
			return m, m.openCreateDialog()
		case "help":
			m.dialog = tuiHelpDialog
			m.dialogScroll = 0
		case "update":
			if m.busyAction == "" && m.updateStatus.Available {
				m.dialog = tuiUpdateDialog
				m.dialogScroll = 0
				m.confirmRemove = false
			}
		}
		return m, nil
	case "page":
		previous := m.page
		m.setPage(target.page)
		if previous != tuiPacketsPage && target.page == tuiPacketsPage {
			return m, m.refreshPacketsCmd()
		}
		return m, nil
	case "cycle-page":
		previous := m.page
		m.cyclePage(target.index)
		if previous != tuiPacketsPage && m.page == tuiPacketsPage {
			return m, m.refreshPacketsCmd()
		}
		return m, nil
	case "table-row":
		cursor, _, count := m.tableState()
		if cursor != nil && target.index >= 0 && target.index < count {
			*cursor = target.index
			m.ensureTableCursorVisible()
		}
		return m, nil
	case "entry-action":
		m.setCursor(target.index)
		switch target.action {
		case "primary":
			return m.primaryAction()
		case "toggle":
			return m.toggleSelected()
		case "edit":
			return m, m.openEditDialog()
		case "delete":
			m.dialog = tuiRemoveDialog
			m.dialogScroll = 0
			m.confirmRemove = false
		}
		return m, nil
	case "shortcut":
		return m.dispatchMouseShortcut(target.action)
	case "entry":
		wasSelected := target.index == m.cursor
		m.setCursor(target.index)
		doubleClick := wasSelected && target.index == m.lastClickIndex && time.Since(m.lastClickAt) <= 450*time.Millisecond
		m.lastClickIndex, m.lastClickAt = target.index, time.Now()
		if !doubleClick {
			return m, nil
		}
		m.lastClickAt = time.Time{}
		if m.page == tuiOverviewPage {
			if m.onNewCard() {
				return m, m.openCreateDialog()
			}
			m.setPage(tuiSandboxesPage)
			return m, nil
		}
		return m.primaryAction()
	}
	return m, nil
}

func (m *sandboxTUIModel) dispatchMouseShortcut(key string) (tea.Model, tea.Cmd) {
	var message tea.KeyPressMsg
	switch key {
	case "enter":
		message.Code = tea.KeyEnter
	case "space":
		message.Code = tea.KeySpace
	case "tab":
		message.Code = tea.KeyTab
	case "esc":
		message.Code = tea.KeyEscape
	default:
		runes := []rune(key)
		if len(runes) != 1 {
			return m, nil
		}
		message.Code = runes[0]
	}
	return m.updateKey(message)
}

func (target tuiHitTarget) String() string {
	parts := []string{target.kind}
	if target.action != "" {
		parts = append(parts, target.action)
	}
	return strings.Join(parts, ":")
}
