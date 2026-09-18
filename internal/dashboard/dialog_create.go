package dashboard

import (
	"strings"

	tea "charm.land/bubbletea/v2"
	dashboardapi "github.com/ejpir/gantry/internal/dashboard/api"
	"github.com/ejpir/gantry/internal/remote"
	"github.com/ejpir/gantry/internal/sandbox/config"
)

func (m *sandboxTUIModel) updateCreateDialogKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.closeDialog()
		return m, nil
	case "tab", "down":
		return m, m.focusCreate((m.createFocus + 1) % 11)
	case "shift+tab", "up":
		return m, m.focusCreate((m.createFocus + 10) % 11)
	case "left", "h":
		if m.adjustCreateChoice(-1) {
			return m, nil
		}
	case "right", "l":
		if m.adjustCreateChoice(1) {
			return m, nil
		}
	case " ", "space":
		if m.createFocus == 2 || m.createFocus == 3 || m.createFocus == 4 || m.createFocus == 5 || m.createFocus == 9 {
			m.adjustCreateChoice(1)
			return m, nil
		}
	case "pgup":
		if m.adjustCreateSlider(8) {
			return m, nil
		}
	case "pgdown":
		if m.adjustCreateSlider(-8) {
			return m, nil
		}
	case "home":
		if m.setCreateSliderBoundary(false) {
			return m, nil
		}
	case "end":
		if m.setCreateSliderBoundary(true) {
			return m, nil
		}
	case "ctrl+enter":
		return m.submitCreate()
	case "enter":
		if m.createFocus < 10 {
			return m, m.focusCreate(m.createFocus + 1)
		}
		return m.submitCreate()
	}

	var cmd tea.Cmd
	switch m.createFocus {
	case 0:
		m.createName, cmd = m.createName.Update(msg)
	case 1:
		m.createImage, cmd = m.createImage.Update(msg)
	}
	m.formError = ""
	m.createErrFocus = -1
	return m, cmd
}

func toggleSandboxSSH(ssh, devContainers *bool) {
	*ssh = !*ssh
	if !*ssh {
		*devContainers = false
	}
}

func (m *sandboxTUIModel) toggleSandboxDevContainers(ssh, devContainers *bool, cpus, memory, disk *resourceSlider, runtime *string) {
	*devContainers = !*devContainers
	if !*devContainers {
		return
	}
	*ssh = true
	cpus.Set(maxInt(cpus.Value, m.limits.DefaultDevContainersVCPUs))
	memory.Set(maxInt(memory.Value, int(m.limits.DefaultDevContainersMemoryMiB)))
	if disk != nil {
		disk.Set(maxInt(disk.Value, int(m.limits.DefaultDevContainersDiskMiB)))
	}
	if runtime != nil {
		*runtime = "crun"
	}
}

func sandboxConfigRequest(name string, ssh, devContainers bool, memory, cpus resourceSlider, isolation string) dashboardapi.SandboxConfigRequest {
	return dashboardapi.SandboxConfigRequest{
		Name: name, SSH: ssh, DevContainers: devContainers,
		MemMB: uint(memory.Value), VCPUs: cpus.Value, ProcessIsolation: isolation,
	}
}

func (m *sandboxTUIModel) adjustCreateChoice(delta int) bool {
	switch m.createFocus {
	case 2:
		if m.createRuntime == "runsc" {
			m.createRuntime = "crun"
		} else {
			m.createRuntime = "runsc"
			m.createDevContainers = false
		}
		return true
	case 3:
		m.cycleCreateKernel(delta)
		return true
	case 4:
		toggleSandboxSSH(&m.createSSH, &m.createDevContainers)
		return true
	case 5:
		m.toggleSandboxDevContainers(&m.createSSH, &m.createDevContainers,
			&m.createCPUs, &m.createMemory, &m.createDisk, &m.createRuntime)
		return true
	case 9:
		m.createIsolation = cycleIsolation(m.createIsolation, delta)
		return true
	default:
		return m.adjustCreateSlider(delta)
	}
}

func (m *sandboxTUIModel) adjustCreateSlider(delta int) bool {
	switch m.createFocus {
	case 6:
		m.createCPUs.Adjust(delta)
		return true
	case 7:
		m.createMemory.Adjust(delta)
		return true
	case 8:
		m.createDisk.Adjust(delta)
		return true
	default:
		return false
	}
}

func (m *sandboxTUIModel) setCreateSliderBoundary(maximum bool) bool {
	var slider *resourceSlider
	switch m.createFocus {
	case 6:
		slider = &m.createCPUs
	case 7:
		slider = &m.createMemory
	case 8:
		slider = &m.createDisk
	default:
		return false
	}
	slider.SetBoundary(maximum)
	return true
}

func (m *sandboxTUIModel) openCreateDialog() tea.Cmd { return m.openCreateForm("", "") }

func (m *sandboxTUIModel) openCreateForm(target, organization string) tea.Cmd {
	m.resetOnboarding()
	m.createRemote, m.createOrganization = target, organization
	m.createEndpoint = remote.Profile{}
	if target != "" {
		m.createEndpoint, _, _ = remote.Lookup(target)
	}
	m.tuiDialogState.openForm(tuiCreateDialog)
	m.createErrFocus = -1
	m.createName.Reset()
	m.createImage.Reset()
	maxCPUs, maxMemory := m.limits.MaxVCPUs, int(m.limits.MaxMemoryMB)
	if target != "" {
		// A remote may be larger than this client. Use protocol/runtime
		// ceilings, not the desktop's RAM; the manager validates capacity.
		maxCPUs, maxMemory = config.MaxSandboxVCPUs(), int(config.MaxSandboxMemMB)
	}
	m.createCPUs = newResourceSlider(1, maxCPUs, 1, 1)
	m.createMemory = newMemorySlider(int(m.limits.MinMemoryMB), maxMemory, 512)
	m.createDisk = newResourceSlider(int(m.limits.MinDiskSizeMiB), int(m.limits.MaxDiskSizeMiB), 512, int(m.limits.DefaultDiskSizeMiB))
	m.createRuntime = "crun"
	m.createKernels = nil
	if target == "" {
		m.createKernels = m.service.KernelChoices()
	}
	m.createKernel = 0
	m.createIsolation = "auto"
	m.createSSH = false
	m.createDevContainers = false
	m.resizeInputs()
	return m.focusCreate(0)
}

func (m *sandboxTUIModel) focusCreate(index int) tea.Cmd {
	m.createFocus = clampInt(index, 0, 10)
	m.createName.Blur()
	m.createImage.Blur()
	m.ensureDialogFocusVisible()
	switch m.createFocus {
	case 0:
		return m.createName.Focus()
	case 1:
		return m.createImage.Focus()
	default:
		return nil
	}
}

func (m *sandboxTUIModel) submitCreate() (tea.Model, tea.Cmd) {
	if m.createRemote != "" {
		return m.submitRemoteCreate()
	}
	name := strings.TrimSpace(m.createName.Value())
	if err := m.service.ValidateCreate(name, uint(m.createMemory.Value), uint(m.createDisk.Value), m.createCPUs.Value, m.createIsolation); err != nil {
		m.formError = err.Error()
		m.createErrFocus = 0
		switch dashboardErrorField(err) {
		case "cpu":
			m.createErrFocus = 6
			return m, m.focusCreate(6)
		case "memory":
			m.createErrFocus = 7
			return m, m.focusCreate(7)
		case "disk":
			m.createErrFocus = 8
			return m, m.focusCreate(8)
		case "isolation":
			m.createErrFocus = 9
			return m, m.focusCreate(9)
		default:
			return m, m.focusCreate(0)
		}
	}
	if err := m.service.ValidateSandboxConfig(sandboxConfigRequest(name, m.createSSH, m.createDevContainers,
		m.createMemory, m.createCPUs, m.createIsolation)); err != nil {
		m.formError = err.Error()
		m.createErrFocus = 5
		return m, m.focusCreate(5)
	}
	return m.beginStart("create", m.createRequest(name))
}
