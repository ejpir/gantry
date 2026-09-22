package dashboard

import tea "charm.land/bubbletea/v2"

func (m *sandboxTUIModel) updateCreateDialogMouse(mouse tea.Mouse, bounds tuiRect) (tea.Model, tea.Cmd) {
	layout := m.createLayout(tuiThemeFor(m.dark), maxInt(10, bounds.w-6))
	x, y := mouse.X-bounds.x-3, mouse.Y-bounds.y-2+m.dialogScroll
	if layout.cancel.contains(x, y) {
		m.closeDialog()
		return m, nil
	}
	if layout.submit.contains(x, y) {
		m.createFocus = createSubmitFocus
		return m.submitCreate()
	}
	focus, ok := createNameFocus, false
	for index, rect := range layout.controls {
		if rect.contains(x, y) {
			focus, ok = index, true
			break
		}
	}
	if !ok {
		return m, nil
	}
	switch focus {
	case createNameFocus, createImageFocus:
		return m, m.focusCreate(focus)
	case createRuntimeFocus, createKernelFocus, createSSHFocus, createDevContainersFocus, createIsolationFocus:
		m.createFocus = focus
		m.adjustCreateChoice(1)
	case createCPUFocus:
		m.setSliderFromMouse(&m.createCPUs, bounds, mouse.X, "CPU")
		return m, m.focusCreate(focus)
	case createMemoryFocus:
		m.setSliderFromMouse(&m.createMemory, bounds, mouse.X, "MiB")
		return m, m.focusCreate(focus)
	case createDiskFocus:
		m.setSliderFromMouse(&m.createDisk, bounds, mouse.X, "MiB")
		return m, m.focusCreate(focus)
	}
	return m, nil
}

func (m *sandboxTUIModel) updateEditDialogMouse(mouse tea.Mouse, bounds tuiRect) (tea.Model, tea.Cmd) {
	if m.dialogButtonHit(mouse, bounds, "Save") {
		m.editFocus = 5
		return m.submitEdit()
	}
	focus, ok := m.dialogFormControlAt(mouse, bounds, []tuiFormControl{
		{label: "SSH", focus: 0}, {label: "Dev Containers", focus: 1},
		{label: "CPUs", focus: 2}, {label: "Memory", focus: 3}, {label: "Process isolation", focus: 4},
	})
	if !ok {
		return m, nil
	}
	switch focus {
	case 0, 1:
		m.editFocus = focus
		m.adjustEditChoice(1)
	case 2:
		m.setSliderFromMouse(&m.editCPUs, bounds, mouse.X, "CPU")
		return m, m.focusEdit(focus)
	case 3:
		m.setSliderFromMouse(&m.editMemory, bounds, mouse.X, "MiB")
		return m, m.focusEdit(focus)
	case 4:
		m.editFocus = focus
		m.editIsolation = cycleIsolation(m.editIsolation, 1)
	}
	return m, nil
}
