package dashboard

import (
	"errors"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
	dashboardapi "github.com/ejpir/gantry/internal/dashboard/api"
)

const (
	dialogBodyRowOffset = 2
	dialogButtonPadding = 2
)

type tuiFormControl struct {
	label string
	focus int
}

func dashboardErrorField(err error) string {
	var fieldErr *dashboardapi.FieldError
	if errors.As(err, &fieldErr) {
		return fieldErr.Field
	}
	return ""
}

// dialogFormControlAt maps a click to controls using the dialog body that was
// actually rendered. Wrapping, compact mode, errors, scrolling, and picker
// menus may all move controls, so no hand-maintained row coordinates are used.
func (m sandboxTUIModel) dialogFormControlAt(mouse tea.Mouse, bounds tuiRect, controls []tuiFormControl) (int, bool) {
	if mouse.X <= bounds.x || mouse.X >= bounds.x+bounds.w-1 {
		return 0, false
	}
	rows, ok := m.dialogFormControlRows(controls)
	if !ok {
		return 0, false
	}
	lines := m.dialogContentLines()
	clickedRow := mouse.Y - bounds.y - dialogBodyRowOffset + m.dialogScroll
	for index, control := range controls {
		last := dialogControlLastRow(index, rows, lines, controls)
		if clickedRow >= rows[index] && clickedRow <= last {
			return control.focus, true
		}
	}
	return 0, false
}

func dialogControlLastRow(index int, rows []int, lines []string, controls []tuiFormControl) int {
	last := len(lines) - 1
	if index+1 < len(rows) {
		last = rows[index+1] - 1
	}
	for row := rows[index] + 1; row <= last && row < len(lines); row++ {
		trimmed := strings.TrimSpace(lines[row])
		if trimmed == "" || dialogSectionHeading(trimmed, controls) {
			return row - 1
		}
	}
	return last
}

func dialogSectionHeading(line string, controls []tuiFormControl) bool {
	if !isUpperDialogHeading(line) {
		return false
	}
	for _, control := range controls {
		if line == strings.ToUpper(control.label) {
			return false
		}
	}
	return true
}

func isUpperDialogHeading(line string) bool {
	if line == "" || line != strings.ToUpper(line) {
		return false
	}
	hasLetter := false
	for _, character := range line {
		if character >= 'A' && character <= 'Z' {
			hasLetter = true
			continue
		}
		if character != ' ' {
			return false
		}
	}
	return hasLetter
}

func (m sandboxTUIModel) dialogFormControlRows(controls []tuiFormControl) ([]int, bool) {
	lines := m.dialogContentLines()
	rows := make([]int, 0, len(controls))
	searchFrom := 0
	for _, control := range controls {
		found := dialogLabelRow(lines, control.label, searchFrom)
		if found < 0 {
			return nil, false
		}
		rows = append(rows, found)
		searchFrom = found + 1
	}
	return rows, true
}

func dialogLabelRow(lines []string, label string, searchFrom int) int {
	for row := searchFrom; row < len(lines); row++ {
		if strings.HasPrefix(strings.TrimSpace(lines[row]), label) {
			return row
		}
	}
	return -1
}

func (m sandboxTUIModel) dialogContentLines() []string {
	_, _, content, _ := m.dialogMeasured(tuiThemeFor(m.dark), m.dialog)
	return strings.Split(ansi.Strip(content), "\n")
}

// chooseDialogSandbox maps an open sandbox picker's rendered menu rows back
// to its visible options. All form dialogs share the same picker rendering.
func (m sandboxTUIModel) chooseDialogSandbox(mouse tea.Mouse, bounds tuiRect, label string, picker *sandboxPicker) bool {
	if picker == nil || !picker.open {
		return false
	}
	rows, ok := m.dialogFormControlRows([]tuiFormControl{{label: label}})
	if !ok {
		return false
	}
	menuTop := dialogPickerMenuTop(m.dialogContentLines(), rows[0]+1)
	if menuTop < 0 {
		return false
	}
	clickedRow := mouse.Y - bounds.y - dialogBodyRowOffset + m.dialogScroll
	return picker.chooseVisible(clickedRow - menuTop - 1)
}

func dialogPickerMenuTop(lines []string, searchFrom int) int {
	borderCount := 0
	for row := searchFrom; row < len(lines); row++ {
		if !strings.Contains(lines[row], "╭") {
			continue
		}
		borderCount++
		if borderCount == 2 {
			return row
		}
	}
	return -1
}

// dialogButtonHit resolves the button from the rendered dialog instead of
// duplicating footer row arithmetic in every form.
func (m sandboxTUIModel) dialogButtonHit(mouse tea.Mouse, bounds tuiRect, label string) bool {
	rect, ok := m.dialogButtonRect(bounds, label)
	return ok && rect.contains(mouse.X, mouse.Y)
}

func (m sandboxTUIModel) dialogButtonRect(bounds tuiRect, label string) (tuiRect, bool) {
	lines := strings.Split(ansi.Strip(m.renderDialog(tuiThemeFor(m.dark))), "\n")
	for row := len(lines) - 1; row >= 0; row-- {
		byteOffset := strings.LastIndex(lines[row], label)
		if byteOffset < 0 {
			continue
		}
		start := maxInt(0, lipgloss.Width(lines[row][:byteOffset])-dialogButtonPadding)
		end := lipgloss.Width(lines[row][:byteOffset+len(label)]) + dialogButtonPadding
		return tuiRect{x: bounds.x + start, y: bounds.y + row, w: end - start, h: 1}, true
	}
	return tuiRect{}, false
}
