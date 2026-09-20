package dashboard

import (
	"strings"

	tea "charm.land/bubbletea/v2"
)

func (m *sandboxTUIModel) openEditDialog() tea.Cmd {
	selected := m.selected()
	if selected == nil {
		return nil
	}
	if selected.Remote != "" {
		return m.showToast(tuiToastInfo, "Remote sandbox", "Configure "+sandboxOperationName(*selected)+" with gantry configure -remote "+selected.Remote+".")
	}
	if selected.ConfigError {
		return m.showToast(tuiToastError, "Cannot edit sandbox", "The saved sandbox configuration is unavailable.")
	}
	m.tuiDialogState.openForm(tuiEditDialog)
	m.editCPUs = newResourceSlider(1, m.limits.MaxVCPUs, 1, maxInt(1, selected.VCPUs))
	m.editMemory = newMemorySlider(int(m.limits.MinMemoryMB), int(m.limits.MaxMemoryMB), int(selected.MemMB))
	m.editIsolation = selected.ProcessIsolation
	if m.editIsolation == "" {
		m.editIsolation = "auto"
	}
	m.editSSH = selected.SSH
	m.editDevContainers = selected.DevContainers
	m.resizeInputs()
	return m.focusEdit(0)
}

func (m *sandboxTUIModel) updateEditDialogKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.closeDialog()
		return m, nil
	case "tab", "down":
		return m, m.focusEdit((m.editFocus + 1) % 6)
	case "shift+tab", "up":
		return m, m.focusEdit((m.editFocus + 5) % 6)
	case "left", "h":
		if m.adjustEditSlider(-1) || m.adjustEditChoice(-1) {
			return m, nil
		}
	case "right", "l":
		if m.adjustEditSlider(1) || m.adjustEditChoice(1) {
			return m, nil
		}
	case " ", "space":
		if m.adjustEditChoice(1) {
			return m, nil
		}
	case "pgup":
		if m.adjustEditSlider(8) {
			return m, nil
		}
	case "pgdown":
		if m.adjustEditSlider(-8) {
			return m, nil
		}
	case "home":
		if m.setEditSliderBoundary(false) {
			return m, nil
		}
	case "end":
		if m.setEditSliderBoundary(true) {
			return m, nil
		}
	case "ctrl+enter":
		return m.submitEdit()
	case "enter":
		if m.editFocus < 5 {
			return m, m.focusEdit(m.editFocus + 1)
		}
		return m.submitEdit()
	}

	m.formError = ""
	return m, nil
}

func (m *sandboxTUIModel) adjustEditChoice(delta int) bool {
	switch m.editFocus {
	case 0:
		m.editFeatureControls().toggleSSH()
		return true
	case 1:
		m.toggleDevContainers(m.editFeatureControls())
		return true
	case 4:
		m.editIsolation = cycleIsolation(m.editIsolation, delta)
		return true
	default:
		return false
	}
}

func (m *sandboxTUIModel) editFeatureControls() sandboxFeatureControls {
	return sandboxFeatureControls{
		ssh: &m.editSSH, devContainers: &m.editDevContainers,
		cpus: &m.editCPUs, memory: &m.editMemory,
	}
}

func (m *sandboxTUIModel) adjustEditSlider(delta int) bool {
	switch m.editFocus {
	case 2:
		m.editCPUs.Adjust(delta)
		return true
	case 3:
		m.editMemory.Adjust(delta)
		return true
	default:
		return false
	}
}

// setEditSliderBoundary mirrors the create dialog's home/end jumps.
func (m *sandboxTUIModel) setEditSliderBoundary(maximum bool) bool {
	var slider *resourceSlider
	switch m.editFocus {
	case 2:
		slider = &m.editCPUs
	case 3:
		slider = &m.editMemory
	default:
		return false
	}
	slider.SetBoundary(maximum)
	return true
}

func (m *sandboxTUIModel) focusEdit(index int) tea.Cmd {
	m.editFocus = clampInt(index, 0, 5)
	m.ensureDialogFocusVisible()
	return nil
}

func (m *sandboxTUIModel) submitEdit() (tea.Model, tea.Cmd) {
	selected := m.selected()
	if selected == nil {
		m.closeDialog()
		return m, nil
	}
	request := (sandboxConfigForm{
		name: selected.Name, ssh: m.editSSH, devContainers: m.editDevContainers,
		memory: m.editMemory, cpus: m.editCPUs, isolation: m.editIsolation,
	}).request()
	if err := m.service.ValidateSandboxConfig(request); err != nil {
		m.formError = err.Error()
		if dashboardErrorField(err) == "devcontainers" {
			return m, m.focusEdit(1)
		}
		if strings.Contains(err.Error(), "CPU") {
			return m, m.focusEdit(2)
		}
		if strings.Contains(err.Error(), "isolation") {
			return m, m.focusEdit(4)
		}
		return m, m.focusEdit(3)
	}
	return m.beginServiceAction("edit", selected.Name,
		saveSandboxConfigCmd(m.service, request, selected.State == tuiRunning))
}

func cycleIsolation(current string, delta int) string {
	choices := []string{"auto", "required", "off"}
	index := 0
	for i, choice := range choices {
		if choice == current {
			index = i
			break
		}
	}
	return choices[(index+delta+len(choices))%len(choices)]
}
