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
	preferred, preferredRemote := "", ""
	if row := m.selectedRule(); row != nil {
		preferred, preferredRemote = row.Sandbox, row.Remote
	} else if sandbox := m.selected(); sandbox != nil {
		preferred, preferredRemote = sandbox.Name, sandbox.Remote
	}
	if !m.policySandbox.ResetWhereSource(m.sandboxes, preferred, preferredRemote, func(sandbox tuiSandbox) bool {
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
	if sandbox := m.sandboxAtSource(m.policySandbox.Value(), m.policySandbox.Remote()); sandbox != nil {
		// A remote policy path belongs to the manager host. Leave the client
		// path blank so choosing a file uploads its JSON rather than confusing
		// the two filesystems.
		if sandbox.Remote == "" {
			m.policyPath.SetValue(sandbox.NetPolicy)
		}
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
	remote := m.policySandbox.Remote()
	service := m.serviceForRemote(remote)
	if err := service.ValidateNetworkPolicy(path, m.policyLocal); err != nil {
		m.formError = err.Error()
		return m, m.focusNetworkPolicy(1)
	}
	return m.beginServiceAction("netpolicy set", remoteOperationLabel(name, remote),
		setSandboxNetworkPolicyCmd(service, name, path, m.policyLocal))
}
