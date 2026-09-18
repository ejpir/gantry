package dashboard

import (
	"time"

	tea "charm.land/bubbletea/v2"
)

func (m *sandboxTUIModel) updateDashboardMouseClick(mouse tea.Mouse) (tea.Model, tea.Cmd) {
	layout := m.dashboardLayout()
	target, ok := m.dashboardHitAt(layout, mouse.X, mouse.Y)
	if !ok {
		return m, nil
	}
	return m.dispatchDashboardHit(target)
}

func (m *sandboxTUIModel) setSliderFromMouse(slider *resourceSlider, bounds tuiRect, mouseX int, suffix string) {
	innerWidth := maxInt(10, bounds.w-6)
	barWidth := slider.barWidth(innerWidth, suffix)
	position := mouseX - (bounds.x + 3)
	if position >= 0 && position < barWidth {
		slider.SetFraction(position, barWidth)
	}
}

func (m *sandboxTUIModel) updateMouseWheel(mouse tea.Mouse) (tea.Model, tea.Cmd) {
	if m.dialog != tuiNoDialog {
		switch mouse.Button {
		case tea.MouseWheelUp:
			m.scrollDialog(-3)
		case tea.MouseWheelDown:
			m.scrollDialog(3)
		}
		return m, nil
	}
	if m.tuiOperationState.Phase() == tuiOperationRunning {
		return m, nil
	}
	m.lastClickAt = time.Time{}
	m.lastClickKind = ""
	if m.page == tuiOverviewPage || m.usesMasterDetail(m.dashboardLayout()) {
		switch mouse.Button {
		case tea.MouseWheelUp:
			m.setCursor(m.cursor - 1)
		case tea.MouseWheelDown:
			m.setCursor(m.cursor + 1)
		}
		return m, nil
	}
	if m.page != tuiSandboxesPage {
		switch mouse.Button {
		case tea.MouseWheelUp:
			m.moveTableCursor(-1)
		case tea.MouseWheelDown:
			m.moveTableCursor(1)
		}
		return m, nil
	}
	switch mouse.Button {
	case tea.MouseWheelUp:
		m.moveCursor(0, -1)
	case tea.MouseWheelDown:
		m.moveCursor(0, 1)
	}
	return m, nil
}
