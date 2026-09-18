package dashboard

import tea "charm.land/bubbletea/v2"

// updateFocusedDialogInput routes text input to the owner of the active form.
// Inactive forms never receive keystrokes.
func (m *sandboxTUIModel) updateFocusedDialogInput(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch m.dialog {
	case tuiOrganizationLoginDialog, tuiRemoteAddDialog:
		cmd = m.updateOnboardInput(msg)
	case tuiSandboxFilterDialog:
		m.sandboxFilterInput, cmd = m.sandboxFilterInput.Update(msg)
	case tuiCreateDialog:
		cmd = m.updateInput(msg)
	case tuiShareAddDialog:
		cmd = m.updateShareInput(msg)
	case tuiPortPublishDialog:
		cmd = m.updatePortInput(msg)
	case tuiNetworkPolicyDialog:
		cmd = m.updatePolicyInput(msg)
	case tuiRuleAddDialog:
		cmd = m.updateRuleInput(msg)
	case tuiSecretAddDialog:
		cmd = m.updateSecretInput(msg)
	case tuiMCPRemoteDialog:
		cmd = m.updateMCPRemoteInput(msg)
	case tuiMCPFilesystemDialog:
		cmd = m.updateMCPFilesystemInput(msg)
	case tuiImagePullDialog:
		cmd = m.updateImagePullInput(msg)
	case tuiRegistryLoginDialog:
		cmd = m.updateRegistryLoginInput(msg)
	}
	return m, cmd
}

func (m *sandboxTUIModel) updateShareInput(msg tea.Msg) (cmd tea.Cmd) {
	switch m.shareFocus {
	case 1:
		m.shareTag, cmd = m.shareTag.Update(msg)
	case 2:
		m.sharePath, cmd = m.sharePath.Update(msg)
	case 3:
		m.shareMount, cmd = m.shareMount.Update(msg)
	case 4:
		m.shareOwner, cmd = m.shareOwner.Update(msg)
	}
	return cmd
}

func (m *sandboxTUIModel) updatePortInput(msg tea.Msg) (cmd tea.Cmd) {
	switch m.portFocus {
	case 1:
		m.portBind, cmd = m.portBind.Update(msg)
	case 2:
		m.portGuest, cmd = m.portGuest.Update(msg)
	}
	return cmd
}

func (m *sandboxTUIModel) updatePolicyInput(msg tea.Msg) (cmd tea.Cmd) {
	if m.policyFocus == 1 {
		m.policyPath, cmd = m.policyPath.Update(msg)
	}
	return cmd
}

func (m *sandboxTUIModel) updateRuleInput(msg tea.Msg) (cmd tea.Cmd) {
	switch m.ruleFocus {
	case 2:
		m.ruleTarget, cmd = m.ruleTarget.Update(msg)
	case 4:
		m.rulePorts, cmd = m.rulePorts.Update(msg)
	}
	return cmd
}

func (m *sandboxTUIModel) updateSecretInput(msg tea.Msg) (cmd tea.Cmd) {
	switch m.secretFocus {
	case 1:
		m.secretName, cmd = m.secretName.Update(msg)
	case 2:
		m.secretValue, cmd = m.secretValue.Update(msg)
	}
	return cmd
}

func (m *sandboxTUIModel) updateMCPRemoteInput(msg tea.Msg) (cmd tea.Cmd) {
	switch m.mcpFocus {
	case 1:
		m.mcpName, cmd = m.mcpName.Update(msg)
	case 2:
		m.mcpURL, cmd = m.mcpURL.Update(msg)
	case 4:
		m.mcpAuthRef, cmd = m.mcpAuthRef.Update(msg)
	case 5:
		m.mcpAuthHeader, cmd = m.mcpAuthHeader.Update(msg)
	case 6:
		m.mcpAllow, cmd = m.mcpAllow.Update(msg)
	case 7:
		m.mcpDeny, cmd = m.mcpDeny.Update(msg)
	case 8:
		m.mcpRedact, cmd = m.mcpRedact.Update(msg)
	}
	return cmd
}

func (m *sandboxTUIModel) updateMCPFilesystemInput(msg tea.Msg) (cmd tea.Cmd) {
	switch m.mcpFSFocus {
	case 1:
		m.mcpFSRoot, cmd = m.mcpFSRoot.Update(msg)
	case 2:
		m.mcpFSUser, cmd = m.mcpFSUser.Update(msg)
	}
	return cmd
}

func (m *sandboxTUIModel) updateImagePullInput(msg tea.Msg) (cmd tea.Cmd) {
	if m.pullFocus == 0 {
		m.pullRef, cmd = m.pullRef.Update(msg)
	}
	return cmd
}

func (m *sandboxTUIModel) updateRegistryLoginInput(msg tea.Msg) (cmd tea.Cmd) {
	switch m.loginFocus {
	case 0:
		m.loginRegistry, cmd = m.loginRegistry.Update(msg)
	case 1:
		m.loginUsername, cmd = m.loginUsername.Update(msg)
	case 2:
		m.loginPassword, cmd = m.loginPassword.Update(msg)
	}
	return cmd
}
