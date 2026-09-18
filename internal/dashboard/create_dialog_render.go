package dashboard

import (
	"fmt"
	"strings"

	"charm.land/lipgloss/v2"
)

type createRenderContext struct {
	theme       tuiTheme
	width       int
	header      string
	description string
	gap         string
	formError   string
}

type createFormSection struct {
	title      string
	start, end int
}

var createFormSections = []createFormSection{
	{title: "Identity", start: createNameFocus, end: createRuntimeFocus},
	{title: "Runtime", start: createRuntimeFocus, end: createSSHFocus},
	{title: "Development", start: createSSHFocus, end: createCPUFocus},
	{title: "Resources", start: createCPUFocus, end: createIsolationFocus},
	{title: "Security", start: createIsolationFocus, end: createSubmitFocus},
}

func (m createDialogModel) render(context createRenderContext) createFormLayout {
	fields, developmentHint := m.createFormFields(context.theme, context.width)
	m.addCreateFormError(fields, context)
	layout, text := layoutCreateFormSections(context, fields, developmentHint)
	layout.text = appendCreateFormActions(context, &layout, text, m.createFocus == createSubmitFocus)
	return layout
}

func (m createDialogModel) createFormFields(theme tuiTheme, width int) ([]string, string) {
	field := func(label, value string, focus int) string {
		return formLabel(theme, label, m.createFocus == focus) + "\n" + value
	}
	focusedValue := func(value, hint string, focus int) string {
		return lipgloss.NewStyle().Bold(m.createFocus == focus).Foreground(theme.text).Render(value) +
			lipgloss.NewStyle().Foreground(theme.muted).Render(hint)
	}
	imageHint := "  optional"
	if m.createRemote != "" {
		imageHint = "  required · pulled remotely if not cached"
	}
	imageLabel := formLabel(theme, "OCI image", m.createFocus == createImageFocus) +
		lipgloss.NewStyle().Foreground(theme.muted).Render(imageHint)
	fields := []string{
		field("Name", renderInputField(theme, m.createName.View(), width, m.createFocus == createNameFocus), createNameFocus),
		imageLabel + "\n" + renderInputField(theme, m.createImage.View(), width, m.createFocus == createImageFocus),
		field("Runtime", focusedValue(m.createRuntime, "  ←/→ or space to change", createRuntimeFocus), createRuntimeFocus),
		field("Kernel", focusedValue(truncateText(m.createKernelLabel(), maxInt(12, width-16)), "  ←/→ to change", createKernelFocus), createKernelFocus),
		field("SSH", renderFeatureToggle(theme, m.createSSH), createSSHFocus),
		field("Dev Containers", renderFeatureToggle(theme, m.createDevContainers), createDevContainersFocus),
		field("CPUs", m.createCPUs.View(theme, width, m.createFocus == createCPUFocus, "CPU"), createCPUFocus),
		field("Memory", m.createMemory.View(theme, width, m.createFocus == createMemoryFocus, "MiB"), createMemoryFocus),
		field("Persistent disk", m.createDisk.View(theme, width, m.createFocus == createDiskFocus, "MiB"), createDiskFocus),
		field("Process isolation", focusedValue(m.createIsolation, "  ←/→ cycles auto / required / off", createIsolationFocus), createIsolationFocus),
	}
	return fields, m.createDevelopmentHint(theme)
}

func (m createDialogModel) createDevelopmentHint(theme tuiTheme) string {
	note := "Adds the curated IDE environment and nested Podman."
	if m.createDevContainers {
		note = fmt.Sprintf("SSH and crun enabled automatically · IDE disk follows Persistent disk (%s)", formatMiBHuman(uint(m.createDisk.Value)))
	}
	return lipgloss.NewStyle().Foreground(theme.muted).Render(note)
}

func (m createDialogModel) addCreateFormError(fields []string, context createRenderContext) {
	if context.formError == "" || m.createErrFocus < 0 || m.createErrFocus >= len(fields) {
		return
	}
	errorLine := lipgloss.NewStyle().Foreground(context.theme.error).
		Render(lipgloss.Wrap(safeUIBlock(context.formError), context.width, ""))
	fields[m.createErrFocus] += "\n" + errorLine
}

func layoutCreateFormSections(context createRenderContext, fields []string, developmentHint string) (createFormLayout, string) {
	layout := createFormLayout{controls: make(map[int]tuiRect)}
	text := lipgloss.Wrap(context.header+"\n"+context.description, context.width, "")
	sectionStyle := lipgloss.NewStyle().Bold(true).Foreground(context.theme.accent)
	for _, section := range createFormSections {
		text += context.gap + lipgloss.Wrap(sectionStyle.Render(strings.ToUpper(section.title)), context.width, "")
		for index := section.start; index < section.end; index++ {
			text += context.gap
			field := lipgloss.Wrap(fields[index], context.width, "")
			layout.controls[index] = tuiRect{x: 0, y: strings.Count(text, "\n"), w: context.width, h: lipgloss.Height(field)}
			text += field
		}
		if section.start == createSSHFocus {
			text += "\n" + lipgloss.Wrap(developmentHint, context.width, "")
		}
	}
	return layout, text
}

func appendCreateFormActions(context createRenderContext, layout *createFormLayout, text string, focused bool) string {
	cancel := renderDialogButton(context.theme, "Cancel", false, false)
	create := renderDialogButton(context.theme, "Create sandbox", focused, false)
	text += "\n\n"
	buttonRow := strings.Count(text, "\n")
	cancelWidth, createWidth := lipgloss.Width(cancel), lipgloss.Width(create)
	if cancelWidth+2+createWidth <= context.width {
		layout.cancel = tuiRect{x: context.width - cancelWidth - 2 - createWidth, y: buttonRow, w: cancelWidth, h: 1}
		layout.submit = tuiRect{x: context.width - createWidth, y: buttonRow, w: createWidth, h: 1}
		text += alignRight(cancel+"  "+create, context.width)
	} else {
		layout.cancel = tuiRect{x: context.width - cancelWidth, y: buttonRow, w: cancelWidth, h: 1}
		layout.submit = tuiRect{x: context.width - createWidth, y: buttonRow + 1, w: createWidth, h: 1}
		text += alignRight(cancel, context.width) + "\n" + alignRight(create, context.width)
	}
	hint := lipgloss.NewStyle().Foreground(context.theme.muted).
		Render("tab next  •  ←/→ change  •  ctrl+enter create  •  esc cancel")
	return text + "\n\n" + lipgloss.Wrap(hint, context.width, "")
}

type createFormLayout struct {
	text           string
	controls       map[int]tuiRect
	cancel, submit tuiRect
}

func (m sandboxTUIModel) createLayout(theme tuiTheme, width int) createFormLayout {
	title := "Create sandbox · Local"
	descriptionText := "Location: Local · Create and boot a persistent microVM on this computer."
	if m.createRemote != "" {
		title = "Create sandbox · " + safeUILine(m.createRemote)
		descriptionText = "Location: Remote " + m.createRemote + " · image pulls and creation run on that manager, never locally."
		if m.createOrganization != "" {
			descriptionText = "Organization: " + m.createOrganization + " · " + descriptionText + " Your signed policy is applied at creation."
		}
	}
	context := createRenderContext{
		theme: theme, width: width, formError: m.formError, gap: m.formSectionGap(),
		header:      m.dialogHeader(theme, title, width),
		description: lipgloss.NewStyle().Foreground(theme.secondary).Render(safeUIBlock(descriptionText)),
	}
	return m.render(context)
}

func (m sandboxTUIModel) renderCreateDialog(theme tuiTheme, width int) string {
	return m.createLayout(theme, width).text
}
