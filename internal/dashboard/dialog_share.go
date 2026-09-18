package dashboard

import (
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"
	dashboardapi "github.com/ejpir/gantry/internal/dashboard/api"
)

func (m *sandboxTUIModel) submitShare() (tea.Model, tea.Cmd) {
	targetName := m.shareSandbox.Value()
	target := m.sandboxNamed(targetName)
	if target == nil || target.State == tuiStarting {
		m.formError = "no eligible sandbox available"
		return m, m.focusShare(0)
	}
	currentGuest := ""
	if row := m.selectedMount(); row != nil {
		currentGuest = row.Guest
	}
	plan, err := m.service.PlanShare(dashboardapi.ShareRequest{
		Sandbox: targetName, Tag: strings.TrimSpace(m.shareTag.Value()),
		Path: strings.TrimSpace(m.sharePath.Value()), Mountpoint: strings.TrimSpace(m.shareMount.Value()),
		Owner: m.shareOwner.Value(), ReadOnly: m.shareRO, Replace: m.shareReplace,
		Running: target.State == tuiRunning, CurrentGuest: currentGuest,
	})
	if err != nil {
		m.formError = err.Error()
		switch dashboardErrorField(err) {
		case "tag":
			return m, m.focusShare(1)
		case "path":
			return m, m.focusShare(2)
		case "mountpoint":
			return m, m.focusShare(3)
		case "owner":
			return m, m.focusShare(4)
		default:
			return m, m.focusShare(0)
		}
	}
	if !plan.Live {
		return m.beginServiceAction("share configure", plan.Sandbox+"/"+plan.Tag,
			configureSandboxShareCmd(m.service, plan, target.State == tuiRunning))
	}
	argv := []string{"share", "add"}
	if plan.Replace {
		argv = append(argv, "--replace")
	}
	argv = append(argv, plan.Sandbox, plan.Spec)
	action := "share add"
	if plan.Replace {
		action = "share replace"
	}
	return m.beginAction(action, plan.Sandbox+"/"+plan.Tag, argv, false)
}

func (m *sandboxTUIModel) removeSelectedShare() (tea.Model, tea.Cmd) {
	row := m.selectedMount()
	if row == nil || row.Error != "" {
		m.closeDialog()
		return m, nil
	}
	return m.beginServiceAction("share remove", row.Sandbox+"/"+row.Tag,
		removeSandboxShareCmd(m.service, *row))
}

func (m *sandboxTUIModel) removeSelected() (tea.Model, tea.Cmd) {
	selected := m.selected()
	if selected == nil {
		m.closeDialog()
		return m, nil
	}
	return m.beginAction("delete", selected.Name, []string{"delete", selected.Name}, false)
}

func (m *sandboxTUIModel) updateShareDialogKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	if m.shareFocus == 0 && m.shareSandbox.HandleKey(msg.String()) {
		return m, nil
	}
	if handled, cmd := m.applyPickerFormKey(msg.String(), m.shareFocus, 6, 5); handled {
		return m, cmd
	}

	var cmd tea.Cmd
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
	m.formError = ""
	return m, cmd
}

func (m *sandboxTUIModel) openShareAddDialog(replace bool) tea.Cmd {
	target := m.shareTargetSandbox()
	if target == nil {
		return m.showToast(tuiToastInfo, "No eligible sandbox", "Wait for a starting sandbox to finish, or create one first.")
	}
	m.tuiDialogState.openForm(tuiShareAddDialog)
	m.shareReplace = replace
	m.shareRO = true
	m.shareTag.Reset()
	m.sharePath.Reset()
	m.shareMount.Reset()
	m.shareOwner.Reset()
	preferred := target.Name
	if replace {
		if row := m.selectedMount(); row != nil && row.Error == "" {
			preferred = row.Sandbox
			m.shareTag.SetValue(row.Tag)
			m.sharePath.SetValue(row.Host)
			if row.Guest != "" && row.Guest != m.service.DefaultShareMount(row.Tag) {
				m.shareMount.SetValue(row.Guest)
			}
			m.shareRO = row.ReadOnly
			if row.UID != nil && row.GID != nil {
				m.shareOwner.SetValue(fmt.Sprintf("%d:%d", *row.UID, *row.GID))
			}
		}
	}
	m.shareSandbox.ResetWhere(m.sandboxes, preferred, func(sandbox tuiSandbox) bool {
		return sandbox.State == tuiRunning || sandbox.State == tuiStopped
	})
	m.resizeInputs()
	return m.focusShare(0)
}

func (m *sandboxTUIModel) focusShare(index int) tea.Cmd {
	m.shareFocus = clampInt(index, 0, 6)
	m.shareTag.Blur()
	m.sharePath.Blur()
	m.shareMount.Blur()
	m.shareOwner.Blur()
	m.ensureDialogFocusVisible()
	switch m.shareFocus {
	case 1:
		return m.shareTag.Focus()
	case 2:
		return m.sharePath.Focus()
	case 3:
		return m.shareMount.Focus()
	case 4:
		return m.shareOwner.Focus()
	default:
		return nil
	}
}
