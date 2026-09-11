package dashboard

import "charm.land/lipgloss/v2"

const (
	tuiWordmark     = "gantry."
	tuiLogoMinWidth = 80
	// The same pair of open-bottom arches as the website's SVG, using ordinary
	// box-drawing characters rather than an image protocol or a custom font.
	tuiLogo = "┌───┐\n│┌─┐│\n││ ││"
)

func renderLogo(theme tuiTheme) string {
	return lipgloss.NewStyle().Foreground(theme.accent).Render(tuiLogo)
}

func renderWordmark(theme tuiTheme) string {
	style := lipgloss.NewStyle().Bold(true)
	return style.Foreground(theme.text).Render(tuiWordmark[:len(tuiWordmark)-1]) +
		style.Foreground(theme.accent).Render(".")
}

// Render the logo in three rows, above the header's dedicated content gap.
// Narrow terminals retain the wordmark and dot without crowding navigation.
func renderHeaderBrand(theme tuiTheme, width int) string {
	wordmark := "\n" + renderWordmark(theme) + "\n"
	if width < tuiLogoMinWidth {
		return wordmark
	}
	return lipgloss.JoinHorizontal(lipgloss.Center, renderLogo(theme), " ", wordmark)
}

// Rendering and mouse/tab geometry must agree on the responsive brand width.
func headerBrandWidth(width int) int {
	brandWidth := lipgloss.Width(tuiWordmark)
	if width >= tuiLogoMinWidth {
		brandWidth += lipgloss.Width(tuiLogo) + 1
	}
	return brandWidth
}
