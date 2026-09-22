package dashboard

import (
	"charm.land/bubbles/v2/textinput"
	"charm.land/lipgloss/v2"
)

func (m *sandboxTUIModel) resizeInputs() {
	setDialogInputWidths(m.dialogFieldWidth(tuiCreateDialog, 12), &m.createName, &m.createImage)
	setDialogInputWidths(m.dialogFieldWidth(tuiShareAddDialog, 12), &m.shareTag, &m.sharePath, &m.shareMount, &m.shareOwner)
	setDialogInputWidths(m.dialogFieldWidth(tuiPortPublishDialog, 12), &m.portBind, &m.portGuest)
	setDialogInputWidths(m.dialogFieldWidth(tuiNetworkPolicyDialog, 12), &m.policyPath)
	setDialogInputWidths(m.dialogFieldWidth(tuiRuleAddDialog, 12), &m.ruleTarget, &m.rulePorts)
	setDialogInputWidths(m.dialogFieldWidth(tuiSecretAddDialog, 12), &m.secretName, &m.secretValue)
	setDialogInputWidths(m.dialogFieldWidth(tuiMCPRemoteDialog, 12),
		&m.mcpName, &m.mcpURL, &m.mcpAuthHeader, &m.mcpAuthRef, &m.mcpAllow,
		&m.mcpDeny, &m.mcpRedact, &m.mcpFSRoot, &m.mcpFSUser)
	setDialogInputWidths(m.dialogFieldWidth(tuiImagePullDialog, 12),
		&m.pullRef, &m.loginRegistry, &m.loginUsername, &m.loginPassword)
	for index := range m.onboardInputs {
		m.onboardInputs[index].SetWidth(m.dialogFieldWidth(m.dialog, 12))
	}
	m.sandboxFilterInput.SetWidth(m.dialogFieldWidth(tuiSandboxFilterDialog, 1))
}

func (m sandboxTUIModel) dialogFieldWidth(dialog tuiDialog, minimum int) int {
	width, _ := m.dialogSize(dialog)
	return maxInt(minimum, width-10)
}

func setDialogInputWidths(width int, inputs ...*textinput.Model) {
	for _, input := range inputs {
		input.SetWidth(width)
	}
}

func (m *sandboxTUIModel) applyInputTheme() {
	theme := tuiThemeFor(m.dark)
	styles := textinput.DefaultStyles(m.dark)
	styles.Focused.Text = lipgloss.NewStyle().Foreground(theme.text)
	styles.Focused.Placeholder = lipgloss.NewStyle().Foreground(theme.muted)
	styles.Focused.Prompt = lipgloss.NewStyle().Foreground(theme.accent)
	styles.Blurred.Text = lipgloss.NewStyle().Foreground(theme.secondary)
	styles.Blurred.Placeholder = lipgloss.NewStyle().Foreground(theme.muted)
	styles.Blurred.Prompt = lipgloss.NewStyle().Foreground(theme.muted)
	styles.Cursor.Color = theme.accent
	applyDialogInputStyles(styles,
		&m.sandboxFilterInput, &m.createName, &m.createImage,
		&m.shareTag, &m.sharePath, &m.shareMount, &m.shareOwner,
		&m.portBind, &m.portGuest, &m.policyPath, &m.ruleTarget, &m.rulePorts,
		&m.secretName, &m.secretValue, &m.mcpName, &m.mcpURL, &m.mcpAuthHeader,
		&m.mcpAuthRef, &m.mcpAllow, &m.mcpDeny, &m.mcpRedact, &m.mcpFSRoot,
		&m.mcpFSUser, &m.pullRef, &m.loginRegistry, &m.loginUsername, &m.loginPassword)
	for index := range m.onboardInputs {
		m.onboardInputs[index].SetStyles(styles)
	}
	m.spinner.Style = lipgloss.NewStyle().Foreground(theme.accent)
}

func applyDialogInputStyles(styles textinput.Styles, inputs ...*textinput.Model) {
	for _, input := range inputs {
		input.SetStyles(styles)
	}
}
