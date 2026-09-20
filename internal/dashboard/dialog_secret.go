package dashboard

import (
	"strings"

	tea "charm.land/bubbletea/v2"
	dashboardapi "github.com/ejpir/gantry/internal/dashboard/api"
	"github.com/ejpir/gantry/internal/secret"
)

func (m *sandboxTUIModel) openSecretAddDialog() tea.Cmd {
	preferred, preferredRemote := "", ""
	if row := m.selectedSecret(); row != nil {
		preferred, preferredRemote = row.Sandbox, row.Remote
	}
	if !m.secretSandbox.ResetWhereSource(m.sandboxes, preferred, preferredRemote, func(sandbox tuiSandbox) bool { return sandbox.State == tuiRunning }) {
		return m.showToast(tuiToastInfo, "No running sandbox", "Start a sandbox before adding an in-memory secret.")
	}
	m.tuiDialogState.openForm(tuiSecretAddDialog)
	m.secretName.Reset()
	m.secretValue.Reset()
	m.resizeInputs()
	return m.focusSecret(0)
}

func (m *sandboxTUIModel) updateSecretAddDialogKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	if m.secretFocus == 0 && m.secretSandbox.HandleKey(msg.String()) {
		return m, nil
	}
	switch msg.String() {
	case "esc":
		m.closeDialog()
		return m, nil
	case "tab", "down":
		return m, m.focusSecret((m.secretFocus + 1) % 4)
	case "shift+tab", "up":
		return m, m.focusSecret((m.secretFocus + 3) % 4)
	case "ctrl+enter":
		return m.submitSecretAdd()
	case "enter":
		if m.secretFocus < 3 {
			return m, m.focusSecret(m.secretFocus + 1)
		}
		return m.submitSecretAdd()
	}
	var cmd tea.Cmd
	switch m.secretFocus {
	case 1:
		m.secretName, cmd = m.secretName.Update(msg)
	case 2:
		m.secretValue, cmd = m.secretValue.Update(msg)
	}
	m.formError = ""
	return m, cmd
}

func (m *sandboxTUIModel) focusSecret(index int) tea.Cmd {
	m.secretFocus = clampInt(index, 0, 3)
	m.secretSandbox.open = false
	m.secretName.Blur()
	m.secretValue.Blur()
	m.ensureDialogFocusVisible()
	switch m.secretFocus {
	case 1:
		return m.secretName.Focus()
	case 2:
		return m.secretValue.Focus()
	default:
		return nil
	}
}

func (m *sandboxTUIModel) submitSecretAdd() (tea.Model, tea.Cmd) {
	request := dashboardapi.SecretRequest{
		Sandbox: m.secretSandbox.Value(), Name: strings.TrimSpace(m.secretName.Value()), Value: secret.Value(m.secretValue.Value()),
	}
	remote := m.secretSandbox.Remote()
	service := m.serviceForRemote(remote)
	if err := service.ValidateSecret(request); err != nil {
		m.formError = err.Error()
		switch dashboardErrorField(err) {
		case "sandbox":
			return m, m.focusSecret(0)
		case "name":
			return m, m.focusSecret(1)
		default:
			return m, m.focusSecret(2)
		}
	}
	m.secretValue.Reset()
	return m.beginServiceAction("secret add", remoteOperationLabel(request.Sandbox+"/"+request.Name, remote),
		addSecretCmd(service, request))
}

func (m *sandboxTUIModel) removeSelectedSecret() (tea.Model, tea.Cmd) {
	row := m.selectedSecret()
	if row == nil {
		m.closeDialog()
		return m, nil
	}
	return m.beginServiceAction("secret remove", remoteOperationLabel(row.Sandbox+"/"+row.Name, row.Remote),
		removeSecretCmd(m.serviceForRemote(row.Remote), *row))
}
