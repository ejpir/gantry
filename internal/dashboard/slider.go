package dashboard

import (
	"fmt"
	"strings"

	"charm.land/lipgloss/v2"
)

// resourceSlider is a small Bubble Tea v2-native slider. The standalone
// hopefulTex/slider bubble is tied to Bubble Tea v1 and exposes neither focus,
// mouse support, nor configurable steps, all of which this form needs.
type resourceSlider struct {
	Min   int
	Max   int
	Step  int
	Value int
}

func newResourceSlider(minimum, maximum, step, value int) resourceSlider {
	s := resourceSlider{Min: minimum, Max: maximum, Step: maxInt(1, step)}
	if value < s.Min {
		// Preserve unusual existing allocations instead of silently raising them
		// merely because the edit dialog was opened.
		s.Min = value
	}
	if value > s.Max {
		s.Max = value
	}
	s.Set(value)
	return s
}

func (s *resourceSlider) Set(value int) {
	s.Value = clampInt(value, s.Min, s.Max)
}

func (s *resourceSlider) Adjust(steps int) {
	s.Set(s.Value + steps*s.Step)
}

func (s *resourceSlider) SetFraction(position, width int) {
	if width <= 1 || s.Max <= s.Min {
		return
	}
	position = clampInt(position, 0, width-1)
	raw := s.Min + (s.Max-s.Min)*position/(width-1)
	raw = s.Min + ((raw-s.Min+s.Step/2)/s.Step)*s.Step
	s.Set(raw)
}

func (s resourceSlider) barWidth(width int, suffix string) int {
	valueWidth := len(fmt.Sprintf("%d %s", s.Value, suffix))
	return maxInt(8, width-valueWidth-4)
}

func (s resourceSlider) View(theme tuiTheme, width int, focused bool, suffix string) string {
	barWidth := s.barWidth(width, suffix)
	position := 0
	if s.Max > s.Min {
		position = (s.Value - s.Min) * (barWidth - 1) / (s.Max - s.Min)
	}
	filled, empty, handle := "━", "─", "◆"
	barColor, valueColor := theme.borderMuted, theme.secondary
	if focused {
		barColor, valueColor = theme.accent, theme.text
	}
	var bar strings.Builder
	for i := 0; i < barWidth; i++ {
		glyph, color := empty, theme.borderMuted
		switch {
		case i == position:
			glyph, color = handle, barColor
		case i < position:
			glyph, color = filled, barColor
		}
		bar.WriteString(lipgloss.NewStyle().Foreground(color).Render(glyph))
	}
	value := lipgloss.NewStyle().Bold(focused).Foreground(valueColor).Render(fmt.Sprintf("%d %s", s.Value, suffix))
	return truncateANSI(bar.String()+"  "+value, width)
}
