package dashboard

import (
	"strings"

	"charm.land/lipgloss/v2"
)

const sandboxPickerMaxVisible = 5

// sandboxPicker is shared by forms whose action belongs to one sandbox.
// Each form supplies its own eligibility rule so saved configuration may
// target a stopped sandbox while live-only actions remain running-only.
type sandboxPicker struct {
	options []string
	cursor  int
	open    bool
}

func (p *sandboxPicker) Reset(sandboxes []tuiSandbox, preferred string) bool {
	return p.ResetWhere(sandboxes, preferred, func(sandbox tuiSandbox) bool {
		return sandbox.State == tuiRunning
	})
}

func (p *sandboxPicker) ResetWhere(sandboxes []tuiSandbox, preferred string, eligible func(tuiSandbox) bool) bool {
	p.options = p.options[:0]
	for _, sandbox := range sandboxes {
		if eligible(sandbox) {
			p.options = append(p.options, sandbox.Name)
		}
	}
	p.cursor = 0
	for i, name := range p.options {
		if name == preferred {
			p.cursor = i
			break
		}
	}
	p.open = false
	return len(p.options) > 0
}

func (p sandboxPicker) Value() string {
	if p.cursor < 0 || p.cursor >= len(p.options) {
		return ""
	}
	return p.options[p.cursor]
}

func (p *sandboxPicker) Move(delta int) {
	if len(p.options) == 0 {
		return
	}
	p.cursor = (p.cursor + delta + len(p.options)) % len(p.options)
}

func (p *sandboxPicker) Toggle() { p.open = !p.open }

// HandleKey owns the interaction contract used by every sandbox picker.
// Up/down remain form navigation while closed; once open they navigate the
// menu. Left/right cycle without opening, and enter/space toggle the menu.
func (p *sandboxPicker) HandleKey(key string) bool {
	if p.open {
		switch key {
		case "esc":
			p.open = false
		case "up", "left":
			p.Move(-1)
		case "down", "right":
			p.Move(1)
		case "enter", " ", "space":
			p.open = false
		default:
			return false
		}
		return true
	}
	switch key {
	case "left":
		p.Move(-1)
	case "right":
		p.Move(1)
	case "enter", " ", "space":
		// Opening an empty picker renders a pointless bordered menu under
		// a field already showing that no sandbox is eligible.
		if len(p.options) > 0 {
			p.open = true
		}
	default:
		return false
	}
	return true
}

func (p sandboxPicker) menuHeight() int {
	if !p.open {
		return 0
	}
	return minInt(len(p.options), sandboxPickerMaxVisible) + 2 // border rows
}

func (p sandboxPicker) visibleStart() int {
	if p.cursor < sandboxPickerMaxVisible {
		return 0
	}
	return p.cursor - sandboxPickerMaxVisible + 1
}

func (p *sandboxPicker) chooseVisible(index int) bool {
	if index < 0 || index >= minInt(len(p.options), sandboxPickerMaxVisible) {
		return false
	}
	p.cursor = p.visibleStart() + index
	p.open = false
	return true
}

func (p sandboxPicker) View(theme tuiTheme, width int, focused bool) string {
	value := p.Value()
	if value == "" {
		value = "no eligible sandbox"
	}
	arrow := "▾"
	if p.open {
		arrow = "▴"
	}
	fieldWidth := maxInt(1, width-4)
	field := renderInputField(theme, joinSides(value, arrow, fieldWidth), width, focused)
	if !p.open {
		return field
	}

	visible := minInt(len(p.options), sandboxPickerMaxVisible)
	start := p.visibleStart()
	lines := make([]string, 0, visible)
	for i := 0; i < visible; i++ {
		option := start + i
		marker := "  "
		style := lipgloss.NewStyle().Foreground(theme.secondary)
		if option == p.cursor {
			marker = "› "
			style = style.Bold(true).Foreground(theme.accent)
		}
		lines = append(lines, style.Render(truncateText(marker+p.options[option], maxInt(1, width-4))))
	}
	menu := lipgloss.NewStyle().
		Foreground(theme.secondary).
		Background(theme.panelRaised).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(theme.borderMuted).
		Padding(0, 1).
		Width(width).
		Render(strings.Join(lines, "\n"))
	return field + "\n" + menu
}
