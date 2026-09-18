package dashboard

import tea "charm.land/bubbletea/v2"

func (m *sandboxTUIModel) updateShareDialogMouse(mouse tea.Mouse, bounds tuiRect) (tea.Model, tea.Cmd) {
	_, _, buttonLabel := m.shareDialogCopy()
	if m.dialogButtonHit(mouse, bounds, buttonLabel) {
		m.shareFocus = 6
		return m.submitShare()
	}
	if m.chooseDialogSandbox(mouse, bounds, "Sandbox", &m.shareSandbox) {
		return m, nil
	}
	focus, ok := m.dialogFormControlAt(mouse, bounds, []tuiFormControl{
		{label: "Sandbox", focus: 0}, {label: "Tag", focus: 1}, {label: "Host path", focus: 2},
		{label: "Mount point", focus: 3}, {label: "Guest owner", focus: 4}, {label: "Mode", focus: 5},
	})
	if !ok {
		return m, nil
	}
	if focus == 0 {
		m.shareSandbox.Toggle()
		return m, m.focusShare(focus)
	}
	if focus >= 1 && focus <= 4 {
		return m, m.focusShare(focus)
	}
	m.shareFocus = focus
	m.shareRO = !m.shareRO
	return m, nil
}

func (m *sandboxTUIModel) updatePortDialogMouse(mouse tea.Mouse, bounds tuiRect) (tea.Model, tea.Cmd) {
	if m.dialogButtonHit(mouse, bounds, "Publish") {
		m.portFocus = 4
		return m.submitPort()
	}
	if m.chooseDialogSandbox(mouse, bounds, "Sandbox", &m.portSandbox) {
		return m, nil
	}
	focus, ok := m.dialogFormControlAt(mouse, bounds, []tuiFormControl{
		{label: "Sandbox", focus: 0}, {label: "Host bind", focus: 1},
		{label: "Guest port", focus: 2}, {label: "Protocol", focus: 3},
	})
	if !ok {
		return m, nil
	}
	switch focus {
	case 0:
		m.portSandbox.Toggle()
		return m, m.focusPort(focus)
	case 1, 2:
		return m, m.focusPort(focus)
	case 3:
		m.portFocus = focus
		m.portUDP = !m.portUDP
	}
	return m, nil
}

func (m *sandboxTUIModel) updateNetworkPolicyDialogMouse(mouse tea.Mouse, bounds tuiRect) (tea.Model, tea.Cmd) {
	if m.dialogButtonHit(mouse, bounds, "Apply") {
		m.policyFocus = 3
		return m.submitNetworkPolicy()
	}
	before := m.policySandbox.Value()
	if m.chooseDialogSandbox(mouse, bounds, "Sandbox", &m.policySandbox) {
		if m.policySandbox.Value() != before {
			m.syncNetworkPolicyFields()
		}
		return m, nil
	}
	focus, ok := m.dialogFormControlAt(mouse, bounds, []tuiFormControl{
		{label: "Sandbox", focus: 0}, {label: "Policy file", focus: 1}, {label: "Local network override", focus: 2},
	})
	if !ok {
		return m, nil
	}
	switch focus {
	case 0:
		m.policySandbox.Toggle()
		return m, m.focusNetworkPolicy(focus)
	case 1:
		return m, m.focusNetworkPolicy(focus)
	case 2:
		m.policyFocus = focus
		m.policyLocal = !m.policyLocal
	}
	return m, nil
}

func (m *sandboxTUIModel) updateRuleAddDialogMouse(mouse tea.Mouse, bounds tuiRect) (tea.Model, tea.Cmd) {
	if m.dialogButtonHit(mouse, bounds, m.ruleAddButtonLabel()) {
		m.ruleFocus = ruleSubmitFocus
		return m.submitRuleAdd()
	}
	if m.chooseDialogSandbox(mouse, bounds, "Sandbox", &m.ruleSandbox) {
		return m, nil
	}
	targetLabel := "Destination"
	if m.ruleProtocol == ruleProtocolDNS {
		targetLabel = "Domain"
	}
	focus, ok := m.dialogFormControlAt(mouse, bounds, []tuiFormControl{
		{label: "Sandbox", focus: ruleSandboxFocus}, {label: "Decision", focus: ruleActionFocus}, {label: targetLabel, focus: ruleTargetFocus},
		{label: "Protocol", focus: ruleProtocolFocus}, {label: "Destination ports", focus: rulePortsFocus},
	})
	if !ok {
		return m, nil
	}
	switch focus {
	case ruleSandboxFocus:
		m.ruleSandbox.Toggle()
		return m, m.focusRule(focus)
	case ruleActionFocus:
		if m.ruleProtocol != ruleProtocolDNS {
			m.ruleFocus = focus
		}
		m.toggleRuleAction()
	case ruleTargetFocus:
		return m, m.focusRule(focus)
	case ruleProtocolFocus:
		if m.ruleProtocol != ruleProtocolDNS {
			m.ruleFocus = focus
		}
		m.changeRuleProtocol(1)
	case rulePortsFocus:
		if m.ruleProtocol != ruleProtocolDNS {
			return m, m.focusRule(focus)
		}
	}
	return m, nil
}

func (m *sandboxTUIModel) updateSecretAddDialogMouse(mouse tea.Mouse, bounds tuiRect) (tea.Model, tea.Cmd) {
	if m.dialogButtonHit(mouse, bounds, "Add secret") {
		m.secretFocus = 3
		return m.submitSecretAdd()
	}
	if m.chooseDialogSandbox(mouse, bounds, "Sandbox", &m.secretSandbox) {
		return m, nil
	}
	focus, ok := m.dialogFormControlAt(mouse, bounds, []tuiFormControl{
		{label: "Sandbox", focus: 0}, {label: "Name", focus: 1}, {label: "Value", focus: 2},
	})
	if !ok {
		return m, nil
	}
	if focus == 0 {
		m.secretSandbox.Toggle()
	}
	return m, m.focusSecret(focus)
}
