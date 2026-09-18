package dashboard

import (
	"errors"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
	dashboardapi "github.com/ejpir/gantry/internal/dashboard/api"
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
// actually rendered. It deliberately has no hand-maintained row coordinates:
// wrapping, compact mode, errors, scrolling, and open picker menus can all move
// controls. A new form only has to list its labels in render order.
func (m sandboxTUIModel) dialogFormControlAt(mouse tea.Mouse, bounds tuiRect, controls []tuiFormControl) (int, bool) {
	if mouse.X <= bounds.x || mouse.X >= bounds.x+bounds.w-1 {
		return 0, false
	}
	rows, ok := m.dialogFormControlRows(controls)
	if !ok {
		return 0, false
	}
	_, _, content, _ := m.dialogMeasured(tuiThemeFor(m.dark), m.dialog)
	lines := strings.Split(ansi.Strip(content), "\n")
	// Dialog borders and top padding consume two visual rows. The viewport's
	// scroll offset maps the click back into the complete, untrimmed body.
	clickedRow := mouse.Y - bounds.y - 2 + m.dialogScroll
	for index, control := range controls {
		last := len(lines) - 1
		if index+1 < len(rows) {
			last = rows[index+1] - 1
		}
		for row := rows[index] + 1; row <= last && row < len(lines); row++ {
			trimmed := strings.TrimSpace(lines[row])
			if trimmed == "" || dialogSectionHeading(trimmed, controls) {
				last = row - 1
				break
			}
		}
		if clickedRow >= rows[index] && clickedRow <= last {
			return control.focus, true
		}
	}
	return 0, false
}

func dialogSectionHeading(line string, controls []tuiFormControl) bool {
	if line == "" || line != strings.ToUpper(line) {
		return false
	}
	for _, control := range controls {
		if line == strings.ToUpper(control.label) {
			return false
		}
	}
	hasLetter := false
	for _, r := range line {
		switch {
		case r >= 'A' && r <= 'Z':
			hasLetter = true
		case r == ' ':
		default:
			return false
		}
	}
	return hasLetter
}

func (m sandboxTUIModel) dialogFormControlRows(controls []tuiFormControl) ([]int, bool) {
	_, _, content, _ := m.dialogMeasured(tuiThemeFor(m.dark), m.dialog)
	lines := strings.Split(ansi.Strip(content), "\n")
	rows := make([]int, 0, len(controls))
	searchFrom := 0
	for _, control := range controls {
		found := -1
		for row := searchFrom; row < len(lines); row++ {
			if strings.HasPrefix(strings.TrimSpace(lines[row]), control.label) {
				found = row
				break
			}
		}
		if found < 0 {
			return nil, false
		}
		rows = append(rows, found)
		searchFrom = found + 1
	}
	return rows, true
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
	_, _, content, _ := m.dialogMeasured(tuiThemeFor(m.dark), m.dialog)
	lines := strings.Split(ansi.Strip(content), "\n")
	menuTop := -1
	borderCount := 0
	for row := rows[0] + 1; row < len(lines); row++ {
		if strings.Contains(lines[row], "╭") {
			borderCount++
			if borderCount == 2 {
				menuTop = row
				break
			}
		}
	}
	if menuTop < 0 {
		return false
	}
	clickedRow := mouse.Y - bounds.y - 2 + m.dialogScroll
	return picker.chooseVisible(clickedRow - menuTop - 1)
}

// dialogButtonHit resolves the button from the rendered dialog instead of
// duplicating footer row arithmetic in every form. Padding around the label is
// included so the visible button and its click target stay together when a
// form gains or loses rows.
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
		start := maxInt(0, lipgloss.Width(lines[row][:byteOffset])-2)
		end := lipgloss.Width(lines[row][:byteOffset+len(label)]) + 2
		return tuiRect{x: bounds.x + start, y: bounds.y + row, w: end - start, h: 1}, true
	}
	return tuiRect{}, false
}
