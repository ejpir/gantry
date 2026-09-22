package dashboard

import (
	"fmt"
	"strconv"
	"strings"

	tea "charm.land/bubbletea/v2"
	"github.com/atotto/clipboard"
	"github.com/charmbracelet/x/ansi"
)

var writeDashboardClipboard = clipboard.WriteAll

type focusedDialogValue struct {
	value string
	label string
}

func (m sandboxTUIModel) copyDialogCmd() tea.Cmd {
	value, label := m.dialogCopyValue()
	return func() tea.Msg {
		return tuiClipboardMsg{label: label, err: writeDashboardClipboard(value)}
	}
}

func (m sandboxTUIModel) dialogCopyValue() (string, string) {
	if value, ok := m.focusedDialogCopyValue(); ok {
		return value.value, value.label
	}
	_, _, content, _ := m.dialogMeasured(tuiThemeFor(m.dark), m.dialog)
	return strings.TrimSpace(ansi.Strip(content)), m.wholeDialogCopyLabel()
}

func (m sandboxTUIModel) focusedDialogCopyValue() (focusedDialogValue, bool) {
	switch m.dialog {
	case tuiCreateDialog:
		return dialogValueAt(m.createFocus, m.createCopyValues())
	case tuiEditDialog:
		return dialogValueAt(m.editFocus, m.editCopyValues())
	case tuiShareAddDialog:
		return dialogValueAt(m.shareFocus, m.shareCopyValues())
	case tuiPortPublishDialog:
		return dialogValueAt(m.portFocus, m.portCopyValues())
	case tuiNetworkPolicyDialog:
		return dialogValueAt(m.policyFocus, m.policyCopyValues())
	case tuiRuleAddDialog:
		return dialogValueAt(m.ruleFocus, m.ruleCopyValues())
	case tuiSecretAddDialog:
		return dialogValueAt(m.secretFocus, m.secretCopyValues())
	case tuiMCPRemoteDialog:
		return dialogValueAt(m.mcpFocus, m.mcpRemoteCopyValues())
	case tuiMCPFilesystemDialog:
		return dialogValueAt(m.mcpFSFocus, m.mcpFilesystemCopyValues())
	case tuiImagePullDialog:
		return dialogValueAt(m.pullFocus, m.imagePullCopyValues())
	case tuiOrganizationLoginDialog:
		return focusedDialogValue{m.onboardURL, "organization authorization URL"}, m.onboardURL != ""
	case tuiRemoteAddDialog:
		// The token is write-only. Whole-dialog copy contains only its masked
		// representation for every other focus position.
		return focusedDialogValue{"", "manager token is write-only"}, m.onboardFocus == 2
	case tuiRegistryLoginDialog:
		// Deliberately omit the password from focused and whole-dialog copies.
		return dialogValueAt(m.loginFocus, m.registryLoginCopyValues())
	default:
		return focusedDialogValue{}, false
	}
}

func dialogValueAt(index int, values []focusedDialogValue) (focusedDialogValue, bool) {
	if index < 0 || index >= len(values) {
		return focusedDialogValue{}, false
	}
	return values[index], true
}

func (m sandboxTUIModel) createCopyValues() []focusedDialogValue {
	return []focusedDialogValue{
		{m.createName.Value(), "sandbox name"},
		{m.createImage.Value(), "OCI image"},
		{m.createRuntime, "runtime"},
		{defaultText(m.createKernelSelection(), "auto"), "kernel"},
		{fmt.Sprint(m.createSSH), "SSH"},
		{fmt.Sprint(m.createDevContainers), "Dev Containers"},
		{strconv.Itoa(m.createCPUs.Value), "CPU count"},
		{strconv.Itoa(m.createMemory.Value), "memory MiB"},
		{strconv.Itoa(m.createDisk.Value), "disk MiB"},
		{m.createIsolation, "process isolation"},
	}
}

func (m sandboxTUIModel) editCopyValues() []focusedDialogValue {
	return []focusedDialogValue{
		{strconv.Itoa(m.editCPUs.Value), "CPU count"},
		{strconv.Itoa(m.editMemory.Value), "memory MiB"},
		{m.editIsolation, "process isolation"},
	}
}

func (m sandboxTUIModel) shareCopyValues() []focusedDialogValue {
	mode := "read-write"
	if m.shareRO {
		mode = "read-only"
	}
	return []focusedDialogValue{
		{m.shareSandbox.Value(), "sandbox"},
		{m.shareTag.Value(), "share tag"},
		{m.sharePath.Value(), "host path"},
		{m.shareMount.Value(), "mount point"},
		{m.shareOwner.Value(), "guest owner"},
		{mode, "share mode"},
	}
}

func (m sandboxTUIModel) portCopyValues() []focusedDialogValue {
	protocol := "tcp"
	if m.portUDP {
		protocol = "udp"
	}
	return []focusedDialogValue{
		{m.portSandbox.Value(), "sandbox"},
		{m.portBind.Value(), "host bind"},
		{m.portGuest.Value(), "guest port"},
		{protocol, "protocol"},
	}
}

func (m sandboxTUIModel) policyCopyValues() []focusedDialogValue {
	local := "blocked"
	if m.policyLocal {
		local = "allowed"
	}
	return []focusedDialogValue{
		{m.policySandbox.Value(), "sandbox"},
		{m.policyPath.Value(), "policy file"},
		{local, "local network override"},
	}
}

func (m sandboxTUIModel) ruleCopyValues() []focusedDialogValue {
	targetLabel := "destination"
	if m.ruleProtocol == ruleProtocolDNS {
		targetLabel = "domain"
	}
	return []focusedDialogValue{
		{m.ruleSandbox.Value(), "sandbox"},
		{m.ruleAction, "decision"},
		{m.ruleTarget.Value(), targetLabel},
		{m.ruleProtocol, "protocol"},
		{m.rulePorts.Value(), "destination ports"},
	}
}

func (m sandboxTUIModel) secretCopyValues() []focusedDialogValue {
	return []focusedDialogValue{
		{m.secretSandbox.Value(), "sandbox"},
		{m.secretName.Value(), "secret name"},
		{m.secretValue.Value(), "secret value"},
	}
}

func (m sandboxTUIModel) mcpRemoteCopyValues() []focusedDialogValue {
	return []focusedDialogValue{
		{m.mcpSandbox.Value(), "sandbox"}, {m.mcpName.Value(), "MCP server name"},
		{m.mcpURL.Value(), "MCP server URL"}, {defaultText(m.mcpAuthKind, "none"), "MCP authentication"},
		{m.mcpAuthRef.Value(), "MCP credential reference"}, {m.mcpAuthHeader.Value(), "MCP header name"},
		{m.mcpAllow.Value(), "MCP allow patterns"}, {m.mcpDeny.Value(), "MCP deny patterns"},
		{m.mcpRedact.Value(), "MCP redact names"},
	}
}

func (m sandboxTUIModel) mcpFilesystemCopyValues() []focusedDialogValue {
	return []focusedDialogValue{
		{m.mcpSandbox.Value(), "sandbox"},
		{m.mcpFSRoot.Value(), "MCP filesystem root"},
		{m.mcpFSUser.Value(), "MCP filesystem user"},
	}
}

func (m sandboxTUIModel) imagePullCopyValues() []focusedDialogValue {
	return []focusedDialogValue{{m.pullRef.Value(), "image reference"}, {m.pullArch, "image architecture"}}
}

func (m sandboxTUIModel) registryLoginCopyValues() []focusedDialogValue {
	return []focusedDialogValue{{m.loginRegistry.Value(), "registry"}, {m.loginUsername.Value(), "registry username"}}
}

func (m sandboxTUIModel) wholeDialogCopyLabel() string {
	switch m.dialog {
	case tuiInfoDialog:
		return "sandbox details"
	case tuiPacketDetailDialog:
		return "packet details"
	case tuiAuditDetailDialog:
		return "audit event"
	case tuiHelpDialog:
		return "keyboard help"
	default:
		return "dialog fields"
	}
}
