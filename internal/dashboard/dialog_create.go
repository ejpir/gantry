package dashboard

import (
	"strings"

	tea "charm.land/bubbletea/v2"
	"github.com/ejpir/gantry/internal/remote"
	"github.com/ejpir/gantry/internal/sandbox/config"
)

func (m *sandboxTUIModel) openCreateDialog() tea.Cmd { return m.openCreateForm("", "") }

func (m *sandboxTUIModel) openCreateForm(target, organization string) tea.Cmd {
	m.resetOnboarding()
	m.createRemote, m.createOrganization = target, organization
	m.createEndpoint = remote.Profile{}
	if target != "" {
		m.createEndpoint, _, _ = remote.Lookup(target)
	}
	m.tuiDialogState.openForm(tuiCreateDialog)
	m.resetCreateForm(target)
	m.resizeInputs()
	return m.focusCreate(createNameFocus)
}

func (m *sandboxTUIModel) resetCreateForm(target string) {
	m.createErrFocus = -1
	m.createName.Reset()
	m.createImage.Reset()
	maxCPUs, maxMemory := m.createResourceMaximums(target)
	m.createCPUs = newResourceSlider(1, maxCPUs, 1, 1)
	m.createMemory = newMemorySlider(int(m.limits.MinMemoryMB), maxMemory, 512)
	m.createDisk = newResourceSlider(int(m.limits.MinDiskSizeMiB), int(m.limits.MaxDiskSizeMiB), 512, int(m.limits.DefaultDiskSizeMiB))
	m.createRuntime = createRuntimeCrun
	m.createKernels = nil
	if target == "" {
		m.createKernels = m.service.KernelChoices()
	}
	m.createKernel = 0
	m.createIsolation = "auto"
	// Remote rows open through the authenticated SSH upgrade, so make terminal
	// access available by default. Users can still disable it explicitly.
	m.createSSH = target != ""
	m.createDevContainers = false
}

func (m sandboxTUIModel) createResourceMaximums(target string) (int, int) {
	if target != "" {
		if section, ok := m.remotes[target]; ok && section.Dashboard != nil {
			limits := section.Dashboard.ResourceLimits
			if limits.MaxVCPUs > 0 && limits.MaxMemoryMB > 0 {
				return limits.MaxVCPUs, int(limits.MaxMemoryMB)
			}
		}
		// An older remote may be larger than this client. Use transport-safe
		// ceilings, not the desktop's capacity; the manager validates its host.
		return config.MaxSandboxVCPUs(), int(config.MaxSandboxMemMB)
	}
	return m.limits.MaxVCPUs, int(m.limits.MaxMemoryMB)
}

func (m *sandboxTUIModel) focusCreate(index int) tea.Cmd {
	m.createFocus = clampInt(index, createNameFocus, createSubmitFocus)
	m.createName.Blur()
	m.createImage.Blur()
	m.ensureDialogFocusVisible()
	switch m.createFocus {
	case createNameFocus:
		return m.createName.Focus()
	case createImageFocus:
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
	if focus, err := m.validateCreateForm(name); err != nil {
		m.formError, m.createErrFocus = err.Error(), focus
		return m, m.focusCreate(focus)
	}
	return m.beginStart("create", m.createRequest(name))
}

func (m sandboxTUIModel) validateCreateForm(name string) (int, error) {
	if err := m.service.ValidateCreate(name, uint(m.createMemory.Value), uint(m.createDisk.Value), m.createCPUs.Value, m.createIsolation); err != nil {
		return createResourceErrorFocus(err), err
	}
	form := sandboxConfigForm{
		name: name, ssh: m.createSSH, devContainers: m.createDevContainers,
		memory: m.createMemory, cpus: m.createCPUs, isolation: m.createIsolation,
	}
	if err := m.service.ValidateSandboxConfig(form.request()); err != nil {
		return createDevContainersFocus, err
	}
	return createNameFocus, nil
}

func createResourceErrorFocus(err error) int {
	switch dashboardErrorField(err) {
	case "cpu":
		return createCPUFocus
	case "memory":
		return createMemoryFocus
	case "disk":
		return createDiskFocus
	case "isolation":
		return createIsolationFocus
	default:
		return createNameFocus
	}
}
