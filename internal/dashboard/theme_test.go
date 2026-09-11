package dashboard

import (
	"fmt"
	"image/color"
	"math"
	"testing"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

func TestDashboardPaletteMatchesWebsite(t *testing.T) {
	for _, tc := range []struct {
		name   string
		dark   bool
		colors []string
	}{
		{"dark", true, []string{"#101210", "#171a17", "#1e221d", "#f0f1e9", "#a6aca0", "#30352e", "#c2f36b"}},
		{"light", false, []string{"#f7f8f3", "#eef1e8", "#e6ebdd", "#202819", "#57634d", "#d2dac7", "#365b19"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			theme := tuiThemeFor(tc.dark)
			colors := []color.Color{theme.bg, theme.panel, theme.panelRaised, theme.text, theme.muted, theme.borderMuted, theme.accent}
			for i, want := range tc.colors {
				if got := colorHex(colors[i]); got != want {
					t.Errorf("palette entry %d = %s, want %s", i, got, want)
				}
			}
		})
	}
}

func TestDashboardThemeTextContrast(t *testing.T) {
	for _, dark := range []bool{true, false} {
		theme := tuiThemeFor(dark)
		foregrounds := map[string]color.Color{
			"text": theme.text, "secondary": theme.secondary, "muted": theme.muted,
			"accent": theme.accent, "success": theme.success, "warning": theme.warning,
			"error": theme.error, "info": theme.info,
		}
		backgrounds := map[string]color.Color{
			"background": theme.bg, "panel": theme.panel,
			"raised": theme.panelRaised, "selected": theme.panelSelected,
		}
		for fgName, foreground := range foregrounds {
			for bgName, background := range backgrounds {
				if ratio := themeContrast(foreground, background); ratio < 4.5 {
					t.Errorf("dark=%t %s on %s: contrast %.2f < 4.5", dark, fgName, bgName, ratio)
				}
			}
		}
		for _, pair := range []struct {
			name       string
			foreground color.Color
			background color.Color
		}{
			{"primary button / kernel band", theme.accentFg, theme.accent},
			{"destructive button", theme.errorFg, theme.error},
		} {
			if ratio := themeContrast(pair.foreground, pair.background); ratio < 4.5 {
				t.Errorf("dark=%t %s: contrast %.2f < 4.5", dark, pair.name, ratio)
			}
		}
	}
}

func TestDashboardThemeFollowsTerminalBackground(t *testing.T) {
	m := modernDashboardTestModel()
	for _, tc := range []struct {
		background string
		dark       bool
	}{{"#ffffff", false}, {"#000000", true}, {"#ffffff", false}} {
		_, _ = m.Update(tea.BackgroundColorMsg{Color: lipgloss.Color(tc.background)})
		if m.dark != tc.dark {
			t.Fatalf("background %s: dark=%t, want %t", tc.background, m.dark, tc.dark)
		}
		theme := tuiThemeFor(tc.dark)
		view := m.View()
		if colorHex(view.BackgroundColor) != colorHex(theme.bg) || colorHex(view.ForegroundColor) != colorHex(theme.text) {
			t.Fatalf("background %s: view did not adopt the website palette", tc.background)
		}
	}
}

func colorHex(c color.Color) string {
	r, g, b, _ := c.RGBA()
	return fmt.Sprintf("#%02x%02x%02x", r>>8, g>>8, b>>8)
}

func themeContrast(a, b color.Color) float64 {
	luminance := func(c color.Color) float64 {
		r, g, b, _ := c.RGBA()
		linear := func(channel uint32) float64 {
			value := float64(channel) / 65535
			if value <= 0.04045 {
				return value / 12.92
			}
			return math.Pow((value+0.055)/1.055, 2.4)
		}
		return 0.2126*linear(r) + 0.7152*linear(g) + 0.0722*linear(b)
	}
	light, dark := luminance(a), luminance(b)
	if light < dark {
		light, dark = dark, light
	}
	return (light + 0.05) / (dark + 0.05)
}
