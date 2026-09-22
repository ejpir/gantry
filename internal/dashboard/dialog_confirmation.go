package dashboard

import tea "charm.land/bubbletea/v2"

func (m *sandboxTUIModel) updateConfirmationDialogKey(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "esc", "q", "n", "N":
		m.closeDialog()
	case "left", "h":
		m.confirmRemove = false
	case "right", "l", "tab", "shift+tab":
		m.confirmRemove = !m.confirmRemove
	case "y", "Y":
		m.confirmRemove = true
		return m.submitConfirmationDialog()
	case "enter":
		if m.confirmRemove {
			return m.submitConfirmationDialog()
		}
		m.closeDialog()
	}
	return m, nil
}

func (m *sandboxTUIModel) submitConfirmationDialog() (tea.Model, tea.Cmd) {
	switch m.dialog {
	case tuiRemoteRemoveDialog:
		return m, m.manageRemoteCmd("remove", m.onboardRemove)
	case tuiRemoveDialog:
		return m.removeSelected()
	case tuiShareRemoveDialog:
		return m.removeSelectedShare()
	case tuiPortUnpublishDialog:
		return m.unpublishSelectedPort()
	case tuiRuleRemoveDialog:
		return m.removeSelectedRule()
	case tuiSecretRemoveDialog:
		return m.removeSelectedSecret()
	case tuiMCPRemoveDialog:
		return m.removeSelectedMCPRemote()
	case tuiUpdateDialog:
		return m.beginUpdate()
	case tuiImageRemoveDialog:
		return m.removeSelectedImage()
	case tuiImagePruneDialog:
		return m.pruneImages()
	case tuiRegistryLogoutDialog:
		return m.logoutSelectedRegistry()
	default:
		return m, nil
	}
}

func (m *sandboxTUIModel) beginUpdate() (tea.Model, tea.Cmd) {
	if !m.updateStatus.Available {
		m.closeDialog()
		return m, nil
	}
	latest := m.updateStatus.Latest
	// No PID handoff: the updater renames the running executable aside and
	// installs in place, so it never has to wait for this process to exit.
	return m.beginAction("update", latest, []string{"update"}, false)
}
