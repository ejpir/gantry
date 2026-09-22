package dashboard

import tea "charm.land/bubbletea/v2"

type tuiFormKeyAction uint8

const (
	tuiFormKeyInput tuiFormKeyAction = iota
	tuiFormKeyClose
	tuiFormKeyFocus
	tuiFormKeyToggle
	tuiFormKeySubmit
)

func classifyFormKey(key string, focus, lastFocus, toggleFocus int) (tuiFormKeyAction, int) {
	switch key {
	case "esc":
		return tuiFormKeyClose, focus
	case "tab", "down":
		return tuiFormKeyFocus, (focus + 1) % (lastFocus + 1)
	case "shift+tab", "up":
		return tuiFormKeyFocus, (focus + lastFocus) % (lastFocus + 1)
	case "left", "right", " ", "space":
		if focus == toggleFocus {
			return tuiFormKeyToggle, focus
		}
	case "ctrl+enter":
		return tuiFormKeySubmit, focus
	case "enter":
		if focus == lastFocus {
			return tuiFormKeySubmit, focus
		}
		return tuiFormKeyFocus, focus + 1
	}
	return tuiFormKeyInput, focus
}

func (m *sandboxTUIModel) applyPickerFormKey(key string, focus, lastFocus, toggleFocus int) (bool, tea.Cmd) {
	action, nextFocus := classifyFormKey(key, focus, lastFocus, toggleFocus)
	switch action {
	case tuiFormKeyClose:
		m.closeDialog()
		return true, nil
	case tuiFormKeyFocus:
		return true, m.focusPickerForm(nextFocus)
	case tuiFormKeyToggle:
		m.togglePickerFormChoice()
		return true, nil
	case tuiFormKeySubmit:
		return true, m.submitPickerForm()
	default:
		return false, nil
	}
}

func (m *sandboxTUIModel) focusPickerForm(index int) tea.Cmd {
	switch m.dialog {
	case tuiShareAddDialog:
		m.shareSandbox.open = false
		return m.focusShare(index)
	case tuiPortPublishDialog:
		m.portSandbox.open = false
		return m.focusPort(index)
	case tuiNetworkPolicyDialog:
		m.policySandbox.open = false
		return m.focusNetworkPolicy(index)
	default:
		return nil
	}
}

func (m *sandboxTUIModel) togglePickerFormChoice() {
	switch m.dialog {
	case tuiShareAddDialog:
		m.shareRO = !m.shareRO
	case tuiPortPublishDialog:
		m.portUDP = !m.portUDP
	case tuiNetworkPolicyDialog:
		m.policyLocal = !m.policyLocal
	}
}

func (m *sandboxTUIModel) submitPickerForm() tea.Cmd {
	var cmd tea.Cmd
	switch m.dialog {
	case tuiShareAddDialog:
		_, cmd = m.submitShare()
	case tuiPortPublishDialog:
		_, cmd = m.submitPort()
	case tuiNetworkPolicyDialog:
		_, cmd = m.submitNetworkPolicy()
	}
	return cmd
}
