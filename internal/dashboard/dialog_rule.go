package dashboard

import (
	"strconv"
	"strings"

	tea "charm.land/bubbletea/v2"
	dashboardapi "github.com/ejpir/gantry/internal/dashboard/api"
)

const (
	ruleSandboxFocus = iota
	ruleActionFocus
	ruleTargetFocus
	ruleProtocolFocus
	rulePortsFocus
	ruleSubmitFocus
)

const (
	ruleActionAllow = "allow"
	ruleActionDeny  = "deny"

	ruleProtocolAny  = "any"
	ruleProtocolTCP  = "tcp"
	ruleProtocolUDP  = "udp"
	ruleProtocolICMP = "icmp"
	ruleProtocolDNS  = "dns"
)

var ruleTransportProtocols = []string{ruleProtocolAny, ruleProtocolTCP, ruleProtocolUDP, ruleProtocolICMP}

func (m *sandboxTUIModel) openRuleAddDialog() tea.Cmd {
	preferred, preferredRemote := "", ""
	if row := m.selectedTraffic(); row != nil {
		preferred, preferredRemote = row.Sandbox, row.Remote
	}
	if !m.ruleSandbox.ResetWhereSource(m.sandboxes, preferred, preferredRemote, ruleEligibleSandbox) {
		return m.showToast(tuiToastInfo, "No eligible sandbox", "Rules require a network-enabled sandbox using the embedded netstack.")
	}
	m.tuiDialogState.openForm(tuiRuleAddDialog)
	m.resetRuleForm()
	if row := m.selectedTraffic(); row != nil {
		m.prefillRuleFromTraffic(*row)
	}
	m.resizeInputs()
	return m.focusRule(ruleSandboxFocus)
}

func ruleEligibleSandbox(sandbox tuiSandbox) bool {
	return sandbox.State != tuiStarting && sandbox.Net && sandbox.GVProxy == ""
}

func (m *sandboxTUIModel) resetRuleForm() {
	m.ruleTarget.Reset()
	m.rulePorts.Reset()
	m.ruleTarget.Placeholder = "203.0.113.10 or 203.0.113.0/24 (blank = all)"
	m.ruleTarget.CharLimit = 64
	m.ruleAction = ruleActionDeny
	m.ruleProtocol = ruleProtocolAny
}

func (m *sandboxTUIModel) prefillRuleFromTraffic(row tuiTrafficRow) {
	if strings.EqualFold(row.Protocol, ruleProtocolDNS) {
		m.ruleTarget.Placeholder = "pi.dev"
		m.ruleTarget.CharLimit = 253
		m.ruleTarget.SetValue(row.Host)
		m.ruleProtocol = ruleProtocolDNS
		m.ruleAction = ruleActionAllow
		return
	}
	m.ruleTarget.SetValue(row.Address)
	switch row.Protocol {
	case ruleProtocolTCP, ruleProtocolUDP, ruleProtocolICMP:
		m.ruleProtocol = row.Protocol
	}
	if row.Port != 0 && ruleProtocolUsesPorts(m.ruleProtocol) {
		m.rulePorts.SetValue(strconv.Itoa(int(row.Port)))
	}
	if !row.Allowed {
		m.ruleAction = ruleActionAllow
	}
}

func (m *sandboxTUIModel) updateRuleAddDialogKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	key := msg.String()
	if m.ruleFocus == ruleSandboxFocus && m.ruleSandbox.HandleKey(key) {
		return m, nil
	}
	switch key {
	case "esc":
		m.closeDialog()
		return m, nil
	case "tab", "down":
		return m, m.advanceRuleFocus(1)
	case "shift+tab", "up":
		return m, m.advanceRuleFocus(-1)
	case "ctrl+enter":
		return m.submitRuleAdd()
	case "enter":
		if m.ruleFocus < ruleSubmitFocus {
			return m, m.advanceRuleFocus(1)
		}
		return m.submitRuleAdd()
	}
	if m.adjustRuleFromKey(key) {
		return m, nil
	}
	cmd := m.updateRuleInput(msg)
	m.formError = ""
	return m, cmd
}

func (m *sandboxTUIModel) adjustRuleFromKey(key string) bool {
	if key != "left" && key != "right" && key != " " && key != "space" {
		return false
	}
	switch m.ruleFocus {
	case ruleActionFocus:
		m.toggleRuleAction()
	case ruleProtocolFocus:
		delta := 1
		if key == "left" {
			delta = -1
		}
		m.changeRuleProtocol(delta)
	default:
		return false
	}
	return true
}

func (m *sandboxTUIModel) toggleRuleAction() {
	if m.ruleProtocol == ruleProtocolDNS {
		return
	}
	if m.ruleAction == ruleActionDeny {
		m.ruleAction = ruleActionAllow
	} else {
		m.ruleAction = ruleActionDeny
	}
}

func (m *sandboxTUIModel) changeRuleProtocol(delta int) {
	if m.ruleProtocol == ruleProtocolDNS {
		return
	}
	m.cycleRuleProtocol(delta)
	if !ruleProtocolUsesPorts(m.ruleProtocol) {
		m.rulePorts.Reset()
	}
}

func ruleProtocolUsesPorts(protocol string) bool {
	return protocol == ruleProtocolTCP || protocol == ruleProtocolUDP
}

func (m *sandboxTUIModel) cycleRuleProtocol(delta int) {
	index := 0
	for candidate, protocol := range ruleTransportProtocols {
		if protocol == m.ruleProtocol {
			index = candidate
			break
		}
	}
	count := len(ruleTransportProtocols)
	m.ruleProtocol = ruleTransportProtocols[(index+delta+count)%count]
}

func (m *sandboxTUIModel) advanceRuleFocus(delta int) tea.Cmd {
	choices := []int{ruleSandboxFocus, ruleActionFocus, ruleTargetFocus, ruleProtocolFocus, rulePortsFocus, ruleSubmitFocus}
	if m.ruleProtocol == ruleProtocolDNS {
		choices = []int{ruleSandboxFocus, ruleTargetFocus, ruleSubmitFocus}
	}
	index := 0
	for candidate, focus := range choices {
		if focus == m.ruleFocus {
			index = candidate
			break
		}
	}
	index = (index + delta + len(choices)) % len(choices)
	return m.focusRule(choices[index])
}

func (m sandboxTUIModel) ruleAddButtonLabel() string {
	if m.ruleProtocol == ruleProtocolDNS {
		return "Allow domain"
	}
	return "Add rule"
}

func (m *sandboxTUIModel) focusRule(index int) tea.Cmd {
	m.ruleFocus = clampInt(index, ruleSandboxFocus, ruleSubmitFocus)
	m.ruleSandbox.open = false
	m.ruleTarget.Blur()
	m.rulePorts.Blur()
	m.ensureDialogFocusVisible()
	switch m.ruleFocus {
	case ruleTargetFocus:
		return m.ruleTarget.Focus()
	case rulePortsFocus:
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
		return m, m.focusRule(ruleSandboxFocus)
	}
	remote := m.ruleSandbox.Remote()
	service := m.serviceForRemote(remote)
	if err := service.ValidateNetworkRule(request); err != nil {
		m.formError = err.Error()
		return m, m.focusRule(ruleErrorFocus(err))
	}
	return m.beginServiceAction("rule add", remoteOperationLabel(request.Sandbox, remote), addNetworkRuleCmd(service, request))
}

func ruleErrorFocus(err error) int {
	switch dashboardErrorField(err) {
	case "action":
		return ruleActionFocus
	case "target":
		return ruleTargetFocus
	case "protocol":
		return ruleProtocolFocus
	default:
		return rulePortsFocus
	}
}

func (m *sandboxTUIModel) removeSelectedRule() (tea.Model, tea.Cmd) {
	row := m.selectedRule()
	if row == nil {
		m.closeDialog()
		return m, nil
	}
	return m.beginServiceAction("rule remove", remoteOperationLabel(row.Sandbox+"/"+row.Source, row.Remote),
		removeNetworkRuleCmd(m.serviceForRemote(row.Remote), *row))
}

func (m *sandboxTUIModel) removeSelectedTrafficRule() (tea.Model, tea.Cmd) {
	row := m.selectedTraffic()
	if row == nil {
		return m, nil
	}
	return m.beginServiceAction("rule remove", remoteOperationLabel(row.Sandbox+"/"+row.Address, row.Remote),
		removeTrafficRuleCmd(m.serviceForRemote(row.Remote), *row))
}
