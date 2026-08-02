package sandbox

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"golang.org/x/term"
)

// CmdTUI runs Gantry's local sandbox dashboard. It intentionally keeps the
// dashboard local-only: Docker's sbx TUI has cloud and governance panels that
// do not apply to Gantry, while the dashboard layout, keyboard flow, cards,
// status bar, and interactive exec handoff are useful for both tools.
func CmdTUI() int {
	if !term.IsTerminal(int(os.Stdin.Fd())) || !term.IsTerminal(int(os.Stdout.Fd())) {
		fmt.Fprintln(os.Stderr, "gantry tui: requires an interactive terminal")
		return 2
	}

	model := newSandboxTUIModel()
	program := tea.NewProgram(
		&model,
		tea.WithInput(os.Stdin),
		tea.WithOutput(os.Stdout),
	)
	if _, err := program.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "gantry tui:", err)
		return 1
	}
	return 0
}

type tuiSandbox struct {
	Name    string
	State   string
	PID     int
	Image   string
	Secrets string
	RW      bool
}

type tuiRefreshMsg struct {
	sandboxes []tuiSandbox
	err       error
	at        time.Time
}

type tuiTickMsg struct{}

type tuiProcessDoneMsg struct {
	action string
	err    error
}

type sandboxTUIModel struct {
	sandboxes  []tuiSandbox
	cursor     int
	width      int
	height     int
	loading    bool
	busy       bool
	confirm    string
	showHelp   bool
	status     string
	lastUpdate time.Time
}

func newSandboxTUIModel() sandboxTUIModel {
	return sandboxTUIModel{
		width:   100,
		height:  30,
		loading: true,
	}
}

func (m sandboxTUIModel) Init() tea.Cmd {
	return tea.Batch(refreshSandboxesCmd(), tuiTickCmd())
}

func (m *sandboxTUIModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil
	case tuiRefreshMsg:
		m.loading = false
		m.lastUpdate = msg.at
		if msg.err != nil {
			m.status = "refresh failed: " + msg.err.Error()
			return m, nil
		}
		selected := ""
		if s := m.selected(); s != nil {
			selected = s.Name
		}
		m.sandboxes = msg.sandboxes
		m.cursor = 0
		for i, s := range m.sandboxes {
			if s.Name == selected {
				m.cursor = i
				break
			}
		}
		if m.cursor >= len(m.sandboxes) {
			m.cursor = maxInt(0, len(m.sandboxes)-1)
		}
		if m.status == "refreshing…" || strings.HasPrefix(m.status, "refresh failed:") {
			m.status = ""
		}
		return m, nil
	case tuiTickMsg:
		if !m.busy {
			m.status = "refreshing…"
			return m, tea.Batch(refreshSandboxesCmd(), tuiTickCmd())
		}
		return m, tuiTickCmd()
	case tuiProcessDoneMsg:
		m.busy = false
		m.confirm = ""
		if msg.err != nil {
			m.status = fmt.Sprintf("%s failed: %v", msg.action, msg.err)
			return m, refreshSandboxesCmd()
		}
		m.status = msg.action + " complete"
		return m, refreshSandboxesCmd()
	case tea.KeyPressMsg:
		return m.updateKey(msg.String())
	}
	return m, nil
}

func (m *sandboxTUIModel) updateKey(key string) (tea.Model, tea.Cmd) {
	if m.confirm != "" {
		switch key {
		case "y", "Y", "enter":
			name := m.confirm
			m.busy = true
			m.status = "deleting " + name + "…"
			return m, m.runProcess("delete", name)
		case "n", "N", "esc", "q":
			m.confirm = ""
		}
		return m, nil
	}
	if m.showHelp {
		switch key {
		case "?", "esc", "q", "enter":
			m.showHelp = false
		}
		return m, nil
	}
	if m.busy {
		return m, nil
	}

	switch key {
	case "q", "ctrl+c":
		return m, func() tea.Msg { return tea.Quit() }
	case "?", "h":
		m.showHelp = true
		return m, nil
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor+1 < len(m.sandboxes) {
			m.cursor++
		}
	case "home", "g":
		m.cursor = 0
	case "end", "G":
		m.cursor = maxInt(0, len(m.sandboxes)-1)
	case "r":
		m.loading = true
		m.status = "refreshing…"
		return m, refreshSandboxesCmd()
	case "enter":
		if s := m.selected(); s != nil {
			if s.State != "running" {
				m.status = fmt.Sprintf("%s is stopped; start it with: gantry start %s", s.Name, s.Name)
				return m, nil
			}
			m.busy = true
			m.status = "opening " + s.Name + "…"
			return m, m.runProcess("exec", s.Name)
		}
	case "s":
		if s := m.selected(); s != nil {
			if s.State != "running" {
				m.status = fmt.Sprintf("%s is stopped; start it with: gantry start %s", s.Name, s.Name)
				return m, nil
			}
			m.busy = true
			m.status = "stopping " + s.Name + "…"
			return m, m.runProcess("stop", s.Name)
		}
	case "d", "delete":
		if s := m.selected(); s != nil {
			m.confirm = s.Name
		}
	}
	return m, nil
}

func (m *sandboxTUIModel) runProcess(action, name string) tea.Cmd {
	exe, err := os.Executable()
	if err != nil {
		return func() tea.Msg { return tuiProcessDoneMsg{action: action, err: err} }
	}
	cmd := exec.Command(exe, action, name)
	return tea.ExecProcess(cmd, func(err error) tea.Msg {
		return tuiProcessDoneMsg{action: action, err: err}
	})
}

func (m sandboxTUIModel) View() tea.View {
	view := tea.NewView(m.render())
	view.AltScreen = true
	view.WindowTitle = "gantry"
	return view
}

func (m sandboxTUIModel) selected() *tuiSandbox {
	if m.cursor < 0 || m.cursor >= len(m.sandboxes) {
		return nil
	}
	return &m.sandboxes[m.cursor]
}

func refreshSandboxesCmd() tea.Cmd {
	return func() tea.Msg {
		sandboxes, err := loadTUISandboxes()
		return tuiRefreshMsg{sandboxes: sandboxes, err: err, at: time.Now()}
	}
}

func tuiTickCmd() tea.Cmd {
	return tea.Tick(2*time.Second, func(time.Time) tea.Msg { return tuiTickMsg{} })
}

func loadTUISandboxes() ([]tuiSandbox, error) {
	entries, err := os.ReadDir(sandboxRoot())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	out := make([]tuiSandbox, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() || !validSandboxName(entry.Name()) {
			continue
		}
		name := entry.Name()
		s := tuiSandbox{Name: name, State: "stopped", Image: "-", Secrets: "-"}
		if pid, alive := sandboxPID(name); alive {
			s.State = "running"
			s.PID = pid
		}
		if b, readErr := os.ReadFile(filepath.Join(sandboxDir(name), "sandbox.json")); readErr == nil {
			var cfg RunConfig
			if json.Unmarshal(b, &cfg) == nil {
				s.Image = cfg.ImageRef
				if s.Image == "" {
					s.Image = filepath.Base(cfg.Image)
				}
				if s.Image == "" {
					s.Image = "-"
				}
				s.RW = cfg.RW
				if len(cfg.SecretNames) > 0 {
					s.Secrets = strings.Join(cfg.SecretNames, ",")
				}
			}
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

var (
	tuiBrandStyle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FF7A3D"))
	tuiTabStyle     = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#7DD3FC"))
	tuiMutedStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("#6B7280"))
	tuiHeadingStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#F3F4F6"))
	tuiKeyStyle     = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FBBF24"))
	tuiRunningStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#34D399"))
	tuiStoppedStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#9CA3AF"))
	tuiErrorStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("#F87171"))
	tuiCardStyle    = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#374151")).
			Padding(0, 1)
	tuiSelectedCardStyle = tuiCardStyle.BorderForeground(lipgloss.Color("#38BDF8"))
)

func (m sandboxTUIModel) render() string {
	width := maxInt(m.width, 40)
	if m.showHelp {
		return m.renderHelp(width)
	}

	header := lipgloss.NewStyle().
		Width(width).
		BorderBottom(true).
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("#374151")).
		Render(lipgloss.JoinHorizontal(lipgloss.Bottom,
			tuiBrandStyle.Render("▰ gantry"),
			"   ",
			tuiTabStyle.Render("SANDBOXES"),
			"   ",
			tuiMutedStyle.Render("local"),
		))

	running := 0
	for _, s := range m.sandboxes {
		if s.State == "running" {
			running++
		}
	}
	summary := lipgloss.JoinHorizontal(lipgloss.Bottom,
		tuiHeadingStyle.Render("Sandboxes"),
		"  ",
		tuiMutedStyle.Render(fmt.Sprintf("%d total · %d running", len(m.sandboxes), running)),
	)

	body := m.renderCards(width)
	footer := m.renderFooter(width)
	return lipgloss.JoinVertical(lipgloss.Left, header, "", summary, "", body, "", footer)
}

func (m sandboxTUIModel) renderCards(width int) string {
	if m.loading && len(m.sandboxes) == 0 {
		return tuiMutedStyle.Render("  Loading sandboxes…")
	}
	if len(m.sandboxes) == 0 {
		return lipgloss.JoinVertical(lipgloss.Left,
			tuiMutedStyle.Render("  No local sandboxes."),
			tuiMutedStyle.Render("  Create one with: gantry start <name> [flags]"),
		)
	}

	cardWidth := maxInt(30, (width-5)/2)
	cards := make([]string, 0, len(m.sandboxes))
	for i, s := range m.sandboxes {
		status := tuiStoppedStyle.Render("○ STOPPED")
		if s.State == "running" {
			status = tuiRunningStyle.Render("● RUNNING")
		}
		name := s.Name
		if i == m.cursor {
			name = tuiKeyStyle.Render("▸ " + name)
		}
		image := s.Image
		if s.RW {
			image += " (rw)"
		}
		lines := []string{
			lipgloss.JoinHorizontal(lipgloss.Bottom, name, "  ", status),
			tuiMutedStyle.Render("image  ") + image,
		}
		if s.State == "running" {
			lines = append(lines, tuiMutedStyle.Render(fmt.Sprintf("pid     %d", s.PID)))
		} else {
			lines = append(lines, tuiMutedStyle.Render("press enter to open when running"))
		}
		if s.Secrets != "-" {
			lines = append(lines, tuiMutedStyle.Render("secrets ")+s.Secrets)
		}
		style := tuiCardStyle
		if i == m.cursor {
			style = tuiSelectedCardStyle
		}
		cards = append(cards, style.Width(cardWidth).Render(strings.Join(lines, "\n")))
	}

	if width < 80 {
		return lipgloss.JoinVertical(lipgloss.Left, cards...)
	}
	var rows []string
	for i := 0; i < len(cards); i += 2 {
		if i+1 < len(cards) {
			rows = append(rows, lipgloss.JoinHorizontal(lipgloss.Top, cards[i], " ", cards[i+1]))
		} else {
			rows = append(rows, cards[i])
		}
	}
	return lipgloss.JoinVertical(lipgloss.Left, rows...)
}

func (m sandboxTUIModel) renderFooter(width int) string {
	var line string
	switch {
	case m.confirm != "":
		line = tuiErrorStyle.Render("Delete "+m.confirm+"? ") + tuiKeyStyle.Render("y") + tuiMutedStyle.Render(" yes  ") + tuiKeyStyle.Render("n") + tuiMutedStyle.Render(" no")
	case m.status != "":
		line = tuiMutedStyle.Render(m.status)
	default:
		line = tuiMutedStyle.Render("↑/↓ select  ") + tuiKeyStyle.Render("enter") + tuiMutedStyle.Render(" open  ") + tuiKeyStyle.Render("s") + tuiMutedStyle.Render(" stop  ") + tuiKeyStyle.Render("d") + tuiMutedStyle.Render(" delete  ") + tuiKeyStyle.Render("r") + tuiMutedStyle.Render(" refresh  ") + tuiKeyStyle.Render("?") + tuiMutedStyle.Render(" help  ") + tuiKeyStyle.Render("q") + tuiMutedStyle.Render(" quit")
	}
	if !m.lastUpdate.IsZero() && m.status == "" {
		line += "  " + tuiMutedStyle.Render("updated "+m.lastUpdate.Format("15:04:05"))
	}
	return lipgloss.NewStyle().Width(width).BorderTop(true).BorderForeground(lipgloss.Color("#374151")).Render(line)
}

func (m sandboxTUIModel) renderHelp(width int) string {
	header := tuiBrandStyle.Render("▰ gantry") + "  " + tuiTabStyle.Render("HELP")
	body := strings.Join([]string{
		header,
		"",
		tuiHeadingStyle.Render("Local sandbox dashboard"),
		"",
		tuiKeyStyle.Render("↑ / k") + " and " + tuiKeyStyle.Render("↓ / j") + "   select a sandbox",
		tuiKeyStyle.Render("enter") + "            open an interactive exec session",
		tuiKeyStyle.Render("s") + "                stop a running sandbox",
		tuiKeyStyle.Render("d") + "                delete a sandbox after confirmation",
		tuiKeyStyle.Render("r") + "                refresh the local sandbox list",
		tuiKeyStyle.Render("?") + " / " + tuiKeyStyle.Render("esc") + "      close this help",
		tuiKeyStyle.Render("q") + "                quit the dashboard",
		"",
		tuiMutedStyle.Render("Start stopped sandboxes from another shell with gantry start <name>.")}, "\n")
	return lipgloss.NewStyle().Width(width).Padding(1, 2).Render(body)
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
