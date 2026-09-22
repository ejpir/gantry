package dashboard

import tea "charm.land/bubbletea/v2"

const createSliderPageStep = 8

func (m *sandboxTUIModel) updateCreateDialogKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	key := msg.String()
	switch key {
	case "esc":
		m.closeDialog()
		return m, nil
	case "tab", "down":
		return m, m.focusCreate((m.createFocus + 1) % createFocusCount)
	case "shift+tab", "up":
		return m, m.focusCreate((m.createFocus + createFocusCount - 1) % createFocusCount)
	case "ctrl+enter":
		return m.submitCreate()
	case "enter":
		if m.createFocus < createSubmitFocus {
			return m, m.focusCreate(m.createFocus + 1)
		}
		return m.submitCreate()
	}
	if m.adjustCreateFromKey(key) {
		return m, nil
	}
	cmd := m.updateInput(msg)
	m.formError = ""
	m.createErrFocus = -1
	return m, cmd
}

func (m *sandboxTUIModel) adjustCreateFromKey(key string) bool {
	switch key {
	case "left", "h":
		return m.adjustCreateChoice(-1)
	case "right", "l":
		return m.adjustCreateChoice(1)
	case " ", "space":
		if m.createFocusAcceptsChoice() {
			return m.adjustCreateChoice(1)
		}
	case "pgup":
		return m.adjustCreateSlider(createSliderPageStep)
	case "pgdown":
		return m.adjustCreateSlider(-createSliderPageStep)
	case "home":
		return m.setCreateSliderBoundary(false)
	case "end":
		return m.setCreateSliderBoundary(true)
	}
	return false
}

func (m sandboxTUIModel) createFocusAcceptsChoice() bool {
	switch m.createFocus {
	case createRuntimeFocus, createKernelFocus, createSSHFocus, createDevContainersFocus, createIsolationFocus:
		return true
	default:
		return false
	}
}

func (m *sandboxTUIModel) adjustCreateChoice(delta int) bool {
	switch m.createFocus {
	case createRuntimeFocus:
		if m.createRuntime == createRuntimeRunsc {
			m.createRuntime = createRuntimeCrun
		} else {
			m.createRuntime = createRuntimeRunsc
			m.createDevContainers = false
		}
	case createKernelFocus:
		m.cycleCreateKernel(delta)
	case createSSHFocus:
		m.createFeatureControls().toggleSSH()
	case createDevContainersFocus:
		m.toggleDevContainers(m.createFeatureControls())
	case createIsolationFocus:
		m.createIsolation = cycleIsolation(m.createIsolation, delta)
	default:
		return m.adjustCreateSlider(delta)
	}
	return true
}

func (m *sandboxTUIModel) createFeatureControls() sandboxFeatureControls {
	return sandboxFeatureControls{
		ssh: &m.createSSH, devContainers: &m.createDevContainers,
		cpus: &m.createCPUs, memory: &m.createMemory, disk: &m.createDisk, runtime: &m.createRuntime,
	}
}

func (m *sandboxTUIModel) adjustCreateSlider(delta int) bool {
	slider := m.focusedCreateSlider()
	if slider == nil {
		return false
	}
	slider.Adjust(delta)
	return true
}

func (m *sandboxTUIModel) setCreateSliderBoundary(maximum bool) bool {
	slider := m.focusedCreateSlider()
	if slider == nil {
		return false
	}
	slider.SetBoundary(maximum)
	return true
}

func (m *sandboxTUIModel) focusedCreateSlider() *resourceSlider {
	switch m.createFocus {
	case createCPUFocus:
		return &m.createCPUs
	case createMemoryFocus:
		return &m.createMemory
	case createDiskFocus:
		return &m.createDisk
	default:
		return nil
	}
}
