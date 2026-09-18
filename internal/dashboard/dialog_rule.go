package dashboard

import (
	"strconv"
	"strings"

	tea "charm.land/bubbletea/v2"
	dashboardapi "github.com/ejpir/gantry/internal/dashboard/api"
)

func (m *sandboxTUIModel) openRuleAddDialog() tea.Cmd {
	preferred := ""
	if row := m.selectedTraffic(); row != nil {
		preferred = row.Sandbox
	}
	if !m.ruleSandbox.ResetWhere(m.sandboxes, preferred, func(sandbox tuiSandbox) bool {
		return sandbox.State != tuiStarting && sandbox.Net && sandbox.GVProxy == ""
	}) {
		return m.showToast(tuiToastInfo, "No eligible sandbox", "Rules require a network-enabled sandbox using the embedded netstack.")
	}
	m.tuiDialogState.openForm(tuiRuleAddDialog)
	m.ruleTarget.Reset()
	m.rulePorts.Reset()
	m.ruleTarget.Placeholder = "203.0.113.10 or 203.0.113.0/24 (blank = all)"
	m.ruleTarget.CharLimit = 64
	m.ruleAction = "deny"
	m.ruleProtocol = "any"
	if row := m.selectedTraffic(); row != nil {
		if strings.EqualFold(row.Protocol, "dns") {
			m.ruleTarget.Placeholder = "pi.dev"
			m.ruleTarget.CharLimit = 253
			m.ruleTarget.SetValue(row.Host)
			m.ruleProtocol = "dns"
			m.ruleAction = "allow"
		} else {
			m.ruleTarget.SetValue(row.Address)
			switch row.Protocol {
			case "tcp", "udp", "icmp":
				m.ruleProtocol = row.Protocol
			}
			if row.Port != 0 && (m.ruleProtocol == "tcp" || m.ruleProtocol == "udp") {
				m.rulePorts.SetValue(strconv.Itoa(int(row.Port)))
			}
			if !row.Allowed {
				m.ruleAction = "allow"
			}
		}
	}
	m.resizeInputs()
	return m.focusRule(0)
}

func (m *sandboxTUIModel) updateRuleAddDialogKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	if m.ruleFocus == 0 && m.ruleSandbox.HandleKey(msg.String()) {
		return m, nil
	}
	key := msg.String()
	switch key {
	case "esc":
		m.closeDialog()
		return m, nil
	case "tab", "down":
		return m, m.advanceRuleFocus(1)
	case "shift+tab", "up":
		return m, m.advanceRuleFocus(-1)
	case "left", "right", " ", "space":
		switch m.ruleFocus {
		case 1:
			m.toggleRuleAction()
			return m, nil
		case 3:
			delta := 1
			if key == "left" {
				delta = -1
			}
			m.changeRuleProtocol(delta)
			return m, nil
		}
	case "ctrl+enter":
		return m.submitRuleAdd()
	case "enter":
		if m.ruleFocus < 5 {
			return m, m.advanceRuleFocus(1)
		}
		return m.submitRuleAdd()
	}
	var cmd tea.Cmd
	switch m.ruleFocus {
	case 2:
		m.ruleTarget, cmd = m.ruleTarget.Update(msg)
	case 4:
		if m.ruleProtocol != "dns" {
			m.rulePorts, cmd = m.rulePorts.Update(msg)
		}
	}
	m.formError = ""
	return m, cmd
}

func (m *sandboxTUIModel) toggleRuleAction() {
	if m.ruleProtocol == "dns" {
		return
	}
	if m.ruleAction == "deny" {
		m.ruleAction = "allow"
	} else {
		m.ruleAction = "deny"
	}
}

func (m *sandboxTUIModel) changeRuleProtocol(delta int) {
	if m.ruleProtocol == "dns" {
		return
	}
	m.cycleRuleProtocol(delta)
	if m.ruleProtocol != "tcp" && m.ruleProtocol != "udp" {
		m.rulePorts.Reset()
	}
}

func (m *sandboxTUIModel) cycleRuleProtocol(delta int) {
	choices := []string{"any", "tcp", "udp", "icmp"}
	index := 0
	for i, choice := range choices {
		if choice == m.ruleProtocol {
			index = i
			break
		}
	}
	m.ruleProtocol = choices[(index+delta+len(choices))%len(choices)]
}

func (m *sandboxTUIModel) advanceRuleFocus(delta int) tea.Cmd {
	choices := []int{0, 1, 2, 3, 4, 5}
	if m.ruleProtocol == "dns" {
		choices = []int{0, 2, 5}
	}
	index := 0
	for i, choice := range choices {
		if choice == m.ruleFocus {
			index = i
			break
		}
	}
	index = (index + delta + len(choices)) % len(choices)
	return m.focusRule(choices[index])
}

func (m sandboxTUIModel) ruleAddButtonLabel() string {
	if m.ruleProtocol == "dns" {
		return "Allow domain"
	}
	return "Add rule"
}

func (m *sandboxTUIModel) focusRule(index int) tea.Cmd {
	m.ruleFocus = clampInt(index, 0, 5)
	m.ruleSandbox.open = false
	m.ruleTarget.Blur()
	m.rulePorts.Blur()
	m.ensureDialogFocusVisible()
	switch m.ruleFocus {
	case 2:
		return m.ruleTarget.Focus()
	case 4:
		return m.rulePorts.Focus()
	default:
		return nil
	}
}

func (m *sandboxTUIModel) submitRuleAdd() (tea.Model, tea.Cmd) {
	request := dashboardapi.RuleRequest{
		Sandbox: m.ruleSandbox.Value(), Action: m.ruleAction,
		Target: strings.TrimSpace(m.ruleTarget.Value()), Proto: m.ruleProtocol,
		Ports: strings.TrimSpace(m.rulePorts.Value()),
	}
	if request.Sandbox == "" {
		m.formError = "no eligible sandbox"
		return m, m.focusRule(0)
	}
	if err := m.service.ValidateNetworkRule(request); err != nil {
		m.formError = err.Error()
		switch dashboardErrorField(err) {
		case "action":
			return m, m.focusRule(1)
		case "target":
			return m, m.focusRule(2)
		case "protocol":
			return m, m.focusRule(3)
		default:
			return m, m.focusRule(4)
		}
	}
	return m.beginServiceAction("rule add", request.Sandbox, addNetworkRuleCmd(m.service, request))
}

func (m *sandboxTUIModel) removeSelectedRule() (tea.Model, tea.Cmd) {
	row := m.selectedRule()
	if row == nil {
		m.closeDialog()
		return m, nil
	}
	return m.beginServiceAction("rule remove", row.Sandbox+"/"+row.Source,
		removeNetworkRuleCmd(m.service, *row))
}

func (m *sandboxTUIModel) removeSelectedTrafficRule() (tea.Model, tea.Cmd) {
	row := m.selectedTraffic()
	if row == nil {
		return m, nil
	}
	return m.beginServiceAction("rule remove", row.Sandbox+"/"+row.Address,
		removeTrafficRuleCmd(m.service, *row))
}
