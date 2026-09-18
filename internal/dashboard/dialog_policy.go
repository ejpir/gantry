package dashboard

import (
	"strings"

	tea "charm.land/bubbletea/v2"
)

func (m *sandboxTUIModel) updateNetworkPolicyDialogKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	if m.policyFocus == 0 {
		before := m.policySandbox.Value()
		if m.policySandbox.HandleKey(msg.String()) {
			if m.policySandbox.Value() != before {
				m.syncNetworkPolicyFields()
			}
			return m, nil
		}
	}
	if handled, cmd := m.applyPickerFormKey(msg.String(), m.policyFocus, 3, 2); handled {
		return m, cmd
	}
	var cmd tea.Cmd
	if m.policyFocus == 1 {
		m.policyPath, cmd = m.policyPath.Update(msg)
	}
	m.formError = ""
	return m, cmd
}

func (m *sandboxTUIModel) openNetworkPolicyDialog() tea.Cmd {
	preferred := ""
	if row := m.selectedRule(); row != nil {
		preferred = row.Sandbox
	} else if sandbox := m.selected(); sandbox != nil {
		preferred = sandbox.Name
	}
	if !m.policySandbox.ResetWhere(m.sandboxes, preferred, func(sandbox tuiSandbox) bool {
		return sandbox.State == tuiRunning && sandbox.Net && sandbox.GVProxy == ""
	}) {
		return m.showToast(tuiToastInfo, "No eligible sandbox", "Live policy updates require a running sandbox with the embedded netstack.")
	}
	m.tuiDialogState.openForm(tuiNetworkPolicyDialog)
	m.syncNetworkPolicyFields()
	m.resizeInputs()
	return m.focusNetworkPolicy(0)
}

func (m *sandboxTUIModel) syncNetworkPolicyFields() {
	m.policyPath.Reset()
	m.policyLocal = false
	if sandbox := m.sandboxNamed(m.policySandbox.Value()); sandbox != nil {
		m.policyPath.SetValue(sandbox.NetPolicy)
		m.policyLocal = sandbox.AllowLocal
	}
}

func (m *sandboxTUIModel) focusNetworkPolicy(index int) tea.Cmd {
	m.policyFocus = clampInt(index, 0, 3)
	m.policyPath.Blur()
	m.ensureDialogFocusVisible()
	if m.policyFocus == 1 {
		return m.policyPath.Focus()
	}
	return nil
}

func (m *sandboxTUIModel) submitNetworkPolicy() (tea.Model, tea.Cmd) {
	name := m.policySandbox.Value()
	if name == "" {
		m.formError = "no eligible running sandbox"
		return m, m.focusNetworkPolicy(0)
	}
	path := strings.TrimSpace(m.policyPath.Value())
	if err := m.service.ValidateNetworkPolicy(path, m.policyLocal); err != nil {
		m.formError = err.Error()
		return m, m.focusNetworkPolicy(1)
	}
	return m.beginServiceAction("netpolicy set", name,
		setSandboxNetworkPolicyCmd(m.service, name, path, m.policyLocal))
}
