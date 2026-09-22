package dashboard

import (
	"fmt"

	tea "charm.land/bubbletea/v2"
	dashboardapi "github.com/ejpir/gantry/internal/dashboard/api"
)

// portSpecFromDialog composes [IP:]HOST:GUEST[/udp] from the dialog fields.
// Split out for tests: blank bind = auto host port on loopback, a bare
// number = loopback + that port, ip:port widens the bind explicitly. Both
// fields are validated strictly BEFORE spec composition: the guest field is
// digits-only, so it can never smuggle an address (e.g. "[::]:80") into the
// bind position, and a bind address must parse as an IP.
func (m *sandboxTUIModel) portSpecFromDialog() (string, error) {
	return m.serviceForRemote(m.portSandbox.Remote()).PlanPort(dashboardapi.PortRequest{
		Bind: m.portBind.Value(), Guest: m.portGuest.Value(), UDP: m.portUDP,
	})
}

func (m *sandboxTUIModel) submitPort() (tea.Model, tea.Cmd) {
	targetName := m.portSandbox.Value()
	if targetName == "" {
		m.formError = "no running sandbox available"
		return m, m.focusPort(0)
	}
	spec, err := m.portSpecFromDialog()
	if err != nil {
		m.formError = err.Error()
		if dashboardErrorField(err) == "guest" {
			return m, m.focusPort(2)
		}
		return m, m.focusPort(1)
	}
	if remote := m.portSandbox.Remote(); remote != "" {
		return m.beginServiceAction("port publish", remoteOperationLabel(targetName+"/"+spec, remote),
			publishPortCmd(m.serviceForRemote(remote), targetName, spec))
	}
	return m.beginAction("port publish", targetName+"/"+spec, []string{"ports", "publish", targetName, spec}, false)
}

func (m *sandboxTUIModel) unpublishSelectedPort() (tea.Model, tea.Cmd) {
	row := m.selectedPort()
	if row == nil || row.Error != "" {
		m.closeDialog()
		return m, nil
	}
	spec := row.Bind + ":" + fmt.Sprintf("%d", row.Guest)
	if row.Proto != "tcp" {
		spec += "/" + row.Proto
	}
	if row.Remote != "" {
		return m.beginServiceAction("port unpublish", remoteOperationLabel(row.Sandbox+"/"+row.Bind, row.Remote),
			unpublishPortCmd(m.serviceForRemote(row.Remote), row.Sandbox, spec))
	}
	return m.beginAction("port unpublish", row.Sandbox+"/"+row.Bind, []string{"ports", "unpublish", row.Sandbox, spec}, false)
}

func (m *sandboxTUIModel) updatePortDialogKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	if m.portFocus == 0 && m.portSandbox.HandleKey(msg.String()) {
		return m, nil
	}
	if handled, cmd := m.applyPickerFormKey(msg.String(), m.portFocus, 4, 3); handled {
		return m, cmd
	}

	var cmd tea.Cmd
	switch m.portFocus {
	case 1:
		m.portBind, cmd = m.portBind.Update(msg)
	case 2:
		m.portGuest, cmd = m.portGuest.Update(msg)
	}
	m.formError = ""
	return m, cmd
}

func (m *sandboxTUIModel) openPortPublishDialog() tea.Cmd {
	target := m.runningTargetSandbox()
	if target == nil {
		return m.showToast(tuiToastInfo, "No running sandbox", "Start a sandbox before publishing a port.")
	}
	if !m.portSandbox.ResetWhereSource(m.sandboxes, target.Name, target.Remote, func(sandbox tuiSandbox) bool {
		return sandbox.State == tuiRunning && sandbox.Net && sandbox.GVProxy == ""
	}) {
		return m.showToast(tuiToastInfo, "No eligible sandbox", "Port publishing requires a running sandbox with the embedded netstack.")
	}
	m.tuiDialogState.openForm(tuiPortPublishDialog)
	m.portUDP = false
	m.portBind.Reset()
	m.portGuest.Reset()
	m.resizeInputs()
	return m.focusPort(0)
}

func (m *sandboxTUIModel) focusPort(index int) tea.Cmd {
	m.portFocus = clampInt(index, 0, 4)
	m.portBind.Blur()
	m.portGuest.Blur()
	m.ensureDialogFocusVisible()
	switch m.portFocus {
	case 1:
		return m.portBind.Focus()
	case 2:
		return m.portGuest.Focus()
	default:
		return nil
	}
}
