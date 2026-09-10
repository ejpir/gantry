package dashboard

import (
	"image/color"

	"charm.land/lipgloss/v2"
)

type tuiTheme struct {
	bg            color.Color
	panel         color.Color
	panelSelected color.Color
	panelRaised   color.Color
	text          color.Color
	secondary     color.Color
	muted         color.Color
	border        color.Color
	borderMuted   color.Color
	accent        color.Color
	accentFg      color.Color
	success       color.Color
	warning       color.Color
	error         color.Color
	errorFg       color.Color
	info          color.Color
}

// Keep the core palette aligned with index.html and the documentation. Terminal
// selection fills and semantic colors supplement those shared surface tokens.
func tuiThemeFor(dark bool) tuiTheme {
	if dark {
		return tuiTheme{
			bg:            lipgloss.Color("#101210"),
			panel:         lipgloss.Color("#171a17"),
			panelSelected: lipgloss.Color("#1c2419"),
			panelRaised:   lipgloss.Color("#1e221d"),
			text:          lipgloss.Color("#f0f1e9"),
			secondary:     lipgloss.Color("#c9d0bf"),
			muted:         lipgloss.Color("#a6aca0"),
			border:        lipgloss.Color("#536344"),
			borderMuted:   lipgloss.Color("#30352e"),
			accent:        lipgloss.Color("#c2f36b"),
			accentFg:      lipgloss.Color("#101210"),
			success:       lipgloss.Color("#a8d58a"),
			warning:       lipgloss.Color("#e6c073"),
			error:         lipgloss.Color("#eaa59b"),
			errorFg:       lipgloss.Color("#101210"),
			info:          lipgloss.Color("#b6c79c"),
		}
	}
	return tuiTheme{
		bg:            lipgloss.Color("#f7f8f3"),
		panel:         lipgloss.Color("#eef1e8"),
		panelSelected: lipgloss.Color("#e8eddf"),
		panelRaised:   lipgloss.Color("#e6ebdd"),
		text:          lipgloss.Color("#202819"),
		secondary:     lipgloss.Color("#404d35"),
		muted:         lipgloss.Color("#57634d"),
		border:        lipgloss.Color("#82936e"),
		borderMuted:   lipgloss.Color("#d2dac7"),
		accent:        lipgloss.Color("#365b19"),
		accentFg:      lipgloss.Color("#ffffff"),
		success:       lipgloss.Color("#3f6b28"),
		warning:       lipgloss.Color("#855513"),
		error:         lipgloss.Color("#9f342e"),
		errorFg:       lipgloss.Color("#ffffff"),
		info:          lipgloss.Color("#516746"),
	}
}
