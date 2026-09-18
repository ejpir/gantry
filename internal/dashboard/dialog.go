package dashboard

import tea "charm.land/bubbletea/v2"

func (m *sandboxTUIModel) updateDialogKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	if handled, cmd := m.updateGlobalDialogKey(msg.String()); handled {
		return m, cmd
	}
	if m.dialog.isOnboarding() {
		return m.updateOnboardingKey(msg)
	}
	if m.dialog.usesConfirmationKeys() {
		return m.updateConfirmationDialogKey(msg.String())
	}
	if m.dialog.isReadOnly() {
		return m.updateReadOnlyDialogKey(msg.String())
	}
	switch m.dialog {
	case tuiSandboxFilterDialog:
		return m.updateFilterDialogKey(msg)
	case tuiSortDialog:
		return m.updateSortDialogKey(msg.String())
	case tuiCreateDialog:
		return m.updateCreateDialogKey(msg)
	case tuiEditDialog:
		return m.updateEditDialogKey(msg)
	case tuiShareAddDialog:
		return m.updateShareDialogKey(msg)
	case tuiPortPublishDialog:
		return m.updatePortDialogKey(msg)
	case tuiNetworkPolicyDialog:
		return m.updateNetworkPolicyDialogKey(msg)
	case tuiRuleAddDialog:
		return m.updateRuleAddDialogKey(msg)
	case tuiSecretAddDialog:
		return m.updateSecretAddDialogKey(msg)
	case tuiMCPRemoteDialog:
		return m.updateMCPRemoteDialogKey(msg)
	case tuiMCPFilesystemDialog:
		return m.updateMCPFilesystemDialogKey(msg)
	case tuiImagePullDialog:
		return m.updateImagePullDialogKey(msg)
	case tuiRegistryLoginDialog:
		return m.updateRegistryLoginDialogKey(msg)
	default:
		return m, nil
	}
}

func (m *sandboxTUIModel) updateGlobalDialogKey(key string) (bool, tea.Cmd) {
	switch key {
	case "ctrl+c":
		return true, m.copyDialogCmd()
	case "ctrl+up":
		m.scrollDialog(-1)
	case "ctrl+down":
		m.scrollDialog(1)
	case "ctrl+pgup":
		m.scrollDialog(-m.dialogViewportHeight())
	case "ctrl+pgdown":
		m.scrollDialog(m.dialogViewportHeight())
	default:
		return false, nil
	}
	return true, nil
}

func (m *sandboxTUIModel) updateReadOnlyDialogKey(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "c":
		return m, m.copyDialogCmd()
	case "esc", "q", "?", "enter", "i", "d":
		m.closeDialog()
	case "up", "k":
		m.scrollDialog(-1)
	case "down", "j":
		m.scrollDialog(1)
	case "pgup":
		m.scrollDialog(-m.dialogViewportHeight())
	case "pgdown", "space", " ":
		m.scrollDialog(m.dialogViewportHeight())
	case "home", "g":
		m.dialogScroll = 0
	case "end", "G":
		m.dialogScroll = m.dialogMaxScroll()
	}
	return m, nil
}
