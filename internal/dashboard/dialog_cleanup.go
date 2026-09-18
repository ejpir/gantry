package dashboard

import "charm.land/lipgloss/v2"

func (m *sandboxTUIModel) closeDialog() {
	m.resetOnboarding()
	m.createDialogModel.releaseFocus()
	m.tuiDialogState.release()
	m.packetDetail = nil
	m.auditDetail = nil
	m.sandboxFilterInput.Blur()
	m.shareDialogState.releaseFocus()
	m.portDialogState.releaseFocus()
	m.policyDialogState.releaseFocus()
	m.ruleDialogState.releaseFocus()
	m.secretDialogState.releaseFocus()
	m.mcpDialogState.releaseFocus()
	m.imageDialogState.releaseFocus()
}

func (m sandboxTUIModel) dialogViewportHeight() int {
	if m.dialog == tuiNoDialog {
		return 1
	}
	_, height, _, _ := m.dialogMeasured(tuiThemeFor(m.dark), m.dialog)
	return maxInt(1, height-4)
}

func (m sandboxTUIModel) dialogMaxScroll() int {
	if m.dialog == tuiNoDialog {
		return 0
	}
	_, height, content, _ := m.dialogMeasured(tuiThemeFor(m.dark), m.dialog)
	return maxInt(0, lipgloss.Height(content)-maxInt(1, height-4))
}

func (m *sandboxTUIModel) scrollDialog(delta int) {
	m.dialogScroll = clampInt(m.dialogScroll+delta, 0, m.dialogMaxScroll())
}
