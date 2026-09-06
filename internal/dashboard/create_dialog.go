package dashboard

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/lifecycle"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

// createDialogModel owns the create form's inputs, launch request, and layout.
// The enclosing dashboard coordinates navigation and asynchronous operations.
type createDialogModel struct {
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

func (m *createDialogModel) updateInput(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	switch m.createFocus {
	case 0:
		m.createName, cmd = m.createName.Update(msg)
	case 1:
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
	if k := m.createKernelSelection(); k != "" {
		return filepath.Base(k)
	}
	if m.createRuntime == "runsc" {
		return "auto (downloads the 4K-page kernel)"
	}
	return "auto (downloads if needed)"
}

func (m createDialogModel) render(theme tuiTheme, width int, header, gap, formError string) createFormLayout {
	description := lipgloss.NewStyle().Foreground(theme.secondary).Render("Create and boot a persistent local microVM.")
	section := func(title string) string {
		return lipgloss.NewStyle().Bold(true).Foreground(theme.accent).Render(strings.ToUpper(title))
	}
	nameLabel := formLabel(theme, "Name", m.createFocus == 0)
	imageLabel := formLabel(theme, "OCI image", m.createFocus == 1) + lipgloss.NewStyle().Foreground(theme.muted).Render("  optional")
	nameField := renderInputField(theme, m.createName.View(), width, m.createFocus == 0)
	imageField := renderInputField(theme, m.createImage.View(), width, m.createFocus == 1)
	runtimeLabel := formLabel(theme, "Runtime", m.createFocus == 2)
	runtimeValue := lipgloss.NewStyle().Bold(m.createFocus == 2).Foreground(theme.text).Render(m.createRuntime) +
		lipgloss.NewStyle().Foreground(theme.muted).Render("  ←/→ or space to change")
	kernelLabel := formLabel(theme, "Kernel", m.createFocus == 3)
	kernelValue := lipgloss.NewStyle().Bold(m.createFocus == 3).Foreground(theme.text).Render(truncateText(m.createKernelLabel(), maxInt(12, width-16))) +
		lipgloss.NewStyle().Foreground(theme.muted).Render("  ←/→ to change")
	sshLabel := formLabel(theme, "SSH", m.createFocus == 4)
	sshValue := renderFeatureToggle(theme, m.createSSH)
	devLabel := formLabel(theme, "Dev Containers", m.createFocus == 5)
	devValue := renderFeatureToggle(theme, m.createDevContainers)
	developmentNote := "Adds the curated IDE environment and nested Podman."
	if m.createDevContainers {
		developmentNote = fmt.Sprintf("SSH and crun enabled automatically · IDE disk follows Persistent disk (%s)", formatMiBHuman(uint(m.createDisk.Value)))
	}
	developmentHint := lipgloss.NewStyle().Foreground(theme.muted).Render(developmentNote)
	cpuLabel := formLabel(theme, "CPUs", m.createFocus == 6)
	cpuSlider := m.createCPUs.View(theme, width, m.createFocus == 6, "CPU")
	memoryLabel := formLabel(theme, "Memory", m.createFocus == 7)
	memorySlider := m.createMemory.View(theme, width, m.createFocus == 7, "MiB")
	diskLabel := formLabel(theme, "Persistent disk", m.createFocus == 8)
	diskSlider := m.createDisk.View(theme, width, m.createFocus == 8, "MiB")
	isolationLabel := formLabel(theme, "Process isolation", m.createFocus == 9)
	isolationValue := lipgloss.NewStyle().Bold(m.createFocus == 9).Foreground(theme.text).Render(m.createIsolation) +
		lipgloss.NewStyle().Foreground(theme.muted).Render("  ←/→ cycles auto / required / off")

	fields := []string{
		nameLabel + "\n" + nameField,
		imageLabel + "\n" + imageField,
		runtimeLabel + "\n" + runtimeValue,
		kernelLabel + "\n" + kernelValue,
		sshLabel + "\n" + sshValue,
		devLabel + "\n" + devValue,
		cpuLabel + "\n" + cpuSlider,
		memoryLabel + "\n" + memorySlider,
		diskLabel + "\n" + diskSlider,
		isolationLabel + "\n" + isolationValue,
	}
	if formError != "" && m.createErrFocus >= 0 && m.createErrFocus < len(fields) {
		errorLine := lipgloss.NewStyle().Foreground(theme.error).Render(lipgloss.Wrap(safeUIBlock(formError), width, ""))
		fields[m.createErrFocus] += "\n" + errorLine
	}

	cancel := renderDialogButton(theme, "Cancel", false, false)
	create := renderDialogButton(theme, "Create sandbox", m.createFocus == 10, false)
	hint := lipgloss.NewStyle().Foreground(theme.muted).Render("tab next  •  ←/→ change  •  ctrl+enter create  •  esc cancel")

	layout := createFormLayout{controls: make(map[int]tuiRect)}
	text := lipgloss.Wrap(header+"\n"+description, width, "")
	sections := []struct {
		title      string
		start, end int
	}{
		{"Identity", 0, 2}, {"Runtime", 2, 4}, {"Development", 4, 6}, {"Resources", 6, 9}, {"Security", 9, 10},
	}
	for _, group := range sections {
		text += gap + lipgloss.Wrap(section(group.title), width, "")
		for index := group.start; index < group.end; index++ {
			text += gap
			field := lipgloss.Wrap(fields[index], width, "")
			layout.controls[index] = tuiRect{x: 0, y: strings.Count(text, "\n"), w: width, h: lipgloss.Height(field)}
			text += field
		}
		if group.title == "Development" {
			text += "\n" + lipgloss.Wrap(developmentHint, width, "")
		}
	}
	text += "\n\n"
	buttonRow := strings.Count(text, "\n")
	cancelWidth, createWidth := lipgloss.Width(cancel), lipgloss.Width(create)
	if cancelWidth+2+createWidth <= width {
		layout.cancel = tuiRect{x: width - cancelWidth - 2 - createWidth, y: buttonRow, w: cancelWidth, h: 1}
		layout.submit = tuiRect{x: width - createWidth, y: buttonRow, w: createWidth, h: 1}
		text += alignRight(cancel+"  "+create, width)
	} else {
		layout.cancel = tuiRect{x: width - cancelWidth, y: buttonRow, w: cancelWidth, h: 1}
		layout.submit = tuiRect{x: width - createWidth, y: buttonRow + 1, w: createWidth, h: 1}
		text += alignRight(cancel, width) + "\n" + alignRight(create, width)
	}
	layout.text = text + "\n\n" + lipgloss.Wrap(hint, width, "")
	return layout
}

type createFormLayout struct {
	text           string
	controls       map[int]tuiRect
	cancel, submit tuiRect
}

func (m sandboxTUIModel) createLayout(theme tuiTheme, width int) createFormLayout {
	return m.render(theme, width, m.dialogHeader(theme, "Create sandbox", width), m.formSectionGap(), m.formError)
}

func (m sandboxTUIModel) renderCreateDialog(theme tuiTheme, width int) string {
	return m.createLayout(theme, width).text
}
