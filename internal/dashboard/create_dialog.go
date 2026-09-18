package dashboard

import (
	"path/filepath"
	"strings"

	"github.com/ejpir/gantry/internal/remote"
	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/lifecycle"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
)

// Create-form controls retain stable positions because keyboard, mouse, error,
// copy, and rendering adapters all refer to the same ordered form.
const (
	createNameFocus = iota
	createImageFocus
	createRuntimeFocus
	createKernelFocus
	createSSHFocus
	createDevContainersFocus
	createCPUFocus
	createMemoryFocus
	createDiskFocus
	createIsolationFocus
	createSubmitFocus
	createFocusCount
)

const (
	createRuntimeCrun  = "crun"
	createRuntimeRunsc = "runsc"
)

// createDialogModel owns the create form's inputs, launch request, and layout.
// The enclosing dashboard coordinates navigation and asynchronous operations.
type createDialogModel struct {
	createRemote        string // empty is explicitly local, never GANTRY_REMOTE
	createEndpoint      remote.Profile
	createOrganization  string // revalidate receipt and snapshot at submission
	createFocus         int
	createErrFocus      int
	createName          textinput.Model
	createImage         textinput.Model
	createCPUs          resourceSlider
	createMemory        resourceSlider
	createDisk          resourceSlider
	createRuntime       string   // "crun" (default) or "runsc"
	createKernels       []string // staged kernel paths; index 0 in the UI is "auto"
	createKernel        int
	createIsolation     string
	createSSH           bool
	createDevContainers bool
}

func (m *createDialogModel) releaseFocus() {
	m.createRemote, m.createOrganization = "", ""
	m.createName.Blur()
	m.createImage.Blur()
}

func (m *createDialogModel) updateInput(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	switch m.createFocus {
	case createNameFocus:
		m.createName, cmd = m.createName.Update(msg)
	case createImageFocus:
		m.createImage, cmd = m.createImage.Update(msg)
	}
	return cmd
}

func (m createDialogModel) createRequest(name string) lifecycle.StartRequest {
	options := config.DefaultRunOptions()
	options.Name, options.Image = name, strings.TrimSpace(m.createImage.Value())
	options.Runtime = m.createRuntime
	if kernel := m.createKernelSelection(); kernel != "" {
		options.Kernel = kernel
		options.Explicit.Kernel = true
	}
	options.SSH, options.DevContainers = m.createSSH, m.createDevContainers
	options.MemMB, options.VCPUs, options.RWLayerSizeMiB = uint(m.createMemory.Value), m.createCPUs.Value, uint(m.createDisk.Value)
	options.Explicit.Memory, options.Explicit.CPUs, options.Explicit.DiskSize = true, true, true
	options.ProcessIsolation = m.createIsolation
	return lifecycle.StartRequest{Name: name, Mode: lifecycle.Create, Options: options}
}

func (m *createDialogModel) cycleCreateKernel(delta int) {
	count := len(m.createKernels) + 1 // +1 for "auto"
	m.createKernel = ((m.createKernel+delta)%count + count) % count
}

// createKernelSelection returns the explicit kernel path, or "" for auto.
func (m *createDialogModel) createKernelSelection() string {
	if m.createKernel <= 0 || m.createKernel > len(m.createKernels) {
		return ""
	}
	return m.createKernels[m.createKernel-1]
}

func (m *createDialogModel) createKernelLabel() string {
	if m.createRemote != "" {
		return "auto (on the remote manager)"
	}
	if k := m.createKernelSelection(); k != "" {
		return filepath.Base(k)
	}
	if m.createRuntime == createRuntimeRunsc {
		return "auto (downloads the 4K-page kernel)"
	}
	return "auto (downloads if needed)"
}
