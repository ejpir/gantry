package dashboard

import tea "charm.land/bubbletea/v2"

func (m *sandboxTUIModel) updateMouseClick(mouse tea.Mouse) (tea.Model, tea.Cmd) {
	if mouse.Button != tea.MouseLeft {
		return m, nil
	}
	if m.dialog == tuiNoDialog && m.toast != nil && m.toastBounds(tuiThemeFor(m.dark)).contains(mouse.X, mouse.Y) {
		m.tuiNotificationState.dismiss()
		return m, nil
	}
	if m.dialog != tuiNoDialog {
		return m.updateDialogMouseClick(mouse)
	}
	return m.updateDashboardMouseClick(mouse)
}

func (m *sandboxTUIModel) updateDialogMouseClick(mouse tea.Mouse) (tea.Model, tea.Cmd) {
	bounds := m.dialogBounds(m.dialog)
	if m.handleDialogChromeClick(mouse, bounds) {
		return m, nil
	}
	if m.dialog.usesConfirmationMouse() {
		return m.updateConfirmationDialogMouse(mouse, bounds)
	}
	if m.dialog.isOnboarding() {
		return m.updateOnboardingMouse(mouse, bounds)
	}
	switch m.dialog {
	case tuiSandboxFilterDialog:
		m.updateFilterDialogMouse(mouse, bounds)
		return m, nil
	case tuiSortDialog:
		m.updateSortDialogMouse(mouse, bounds)
		return m, nil
	case tuiCreateDialog:
		return m.updateCreateDialogMouse(mouse, bounds)
	case tuiEditDialog:
		return m.updateEditDialogMouse(mouse, bounds)
	case tuiShareAddDialog:
		return m.updateShareDialogMouse(mouse, bounds)
	case tuiPortPublishDialog:
		return m.updatePortDialogMouse(mouse, bounds)
	case tuiNetworkPolicyDialog:
		return m.updateNetworkPolicyDialogMouse(mouse, bounds)
	case tuiRuleAddDialog:
		return m.updateRuleAddDialogMouse(mouse, bounds)
	case tuiSecretAddDialog:
		return m.updateSecretAddDialogMouse(mouse, bounds)
	case tuiMCPRemoteDialog:
		return m.updateMCPRemoteDialogMouse(mouse, bounds)
	case tuiMCPFilesystemDialog:
		return m.updateMCPFilesystemDialogMouse(mouse, bounds)
	case tuiImagePullDialog:
		return m.updateImagePullDialogMouse(mouse, bounds)
	case tuiRegistryLoginDialog:
		return m.updateRegistryLoginDialogMouse(mouse, bounds)
	default:
		return m, nil
	}
}

func (m *sandboxTUIModel) handleDialogChromeClick(mouse tea.Mouse, bounds tuiRect) bool {
	if !bounds.contains(mouse.X, mouse.Y) {
		m.closeDialog()
		return true
	}
	if mouse.X == bounds.x+bounds.w-2 && mouse.Y >= bounds.y+2 && mouse.Y < bounds.y+bounds.h-2 {
		viewport := m.dialogViewportHeight()
		maxScroll := m.dialogMaxScroll()
		if maxScroll > 0 {
			trackRow := clampInt(mouse.Y-(bounds.y+2), 0, viewport-1)
			m.dialogScroll = trackRow * maxScroll / maxInt(1, viewport-1)
			return true
		}
	}
	// Every dialog has a close glyph in its title row (the dialog has one
	// row of border and one row of vertical padding above it).
	if mouse.Y >= bounds.y+1 && mouse.Y <= bounds.y+3 && mouse.X >= bounds.x+bounds.w-6 {
		m.closeDialog()
		return true
	}
	return false
}

func (m *sandboxTUIModel) updateFilterDialogMouse(mouse tea.Mouse, bounds tuiRect) {
	if m.dialogButtonHit(mouse, bounds, "Apply") {
		m.applySandboxFilter(m.sandboxFilterInput.Value())
		m.closeDialog()
	} else if m.dialogButtonHit(mouse, bounds, "Clear") {
		m.applySandboxFilter("")
		m.closeDialog()
	}
}

func (m *sandboxTUIModel) updateSortDialogMouse(mouse tea.Mouse, bounds tuiRect) {
	if mouse.X < bounds.x+3 || mouse.X >= bounds.x+bounds.w-3 {
		return
	}
	_, options := m.sortDialogLayout(tuiThemeFor(m.dark), maxInt(10, bounds.w-6))
	row := mouse.Y - bounds.y - 2 + m.dialogScroll
	for _, option := range options {
		if option.row == row {
			m.chooseSort(option.id)
			m.closeDialog()
			return
		}
	}
}

func (m *sandboxTUIModel) updateConfirmationDialogMouse(mouse tea.Mouse, bounds tuiRect) (tea.Model, tea.Cmd) {
	if m.dialogButtonHit(mouse, bounds, "Cancel") {
		m.confirmRemove = false
		m.closeDialog()
		return m, nil
	}
	if action := m.confirmationActionLabel(); action != "" && m.dialogButtonHit(mouse, bounds, action) {
		m.confirmRemove = true
		return m.submitConfirmationDialog()
	}
	return m, nil
}

func (m sandboxTUIModel) confirmationActionLabel() string {
	switch m.dialog {
	case tuiRemoveDialog, tuiShareRemoveDialog, tuiRuleRemoveDialog, tuiRemoteRemoveDialog:
		return "Remove"
	case tuiPortUnpublishDialog:
		return "Unpublish"
	case tuiSecretRemoveDialog:
		return "Delete"
	case tuiMCPRemoveDialog:
		return "Remove"
	case tuiUpdateDialog:
		return "Update"
	case tuiImageRemoveDialog:
		return "Remove"
	case tuiImagePruneDialog:
		return "Prune"
	case tuiRegistryLogoutDialog:
		return "Logout"
	default:
		return ""
	}
}
