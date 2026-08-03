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

	"gantry/internal/netpol"
	"gantry/internal/shares"

	"charm.land/bubbles/v2/spinner"
	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"golang.org/x/term"
)

// CmdTUI runs Gantry's local sandbox dashboard.
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

type tuiSandboxState string

const (
	tuiStopped  tuiSandboxState = "stopped"
	tuiStarting tuiSandboxState = "starting"
	tuiRunning  tuiSandboxState = "running"
)

type tuiPage uint8

const (
	tuiSandboxesPage tuiPage = iota
	tuiTrafficPage
	tuiRulesPage
	tuiMountsPage
	tuiPageCount
)

type tuiSandbox struct {
	Name             string
	State            tuiSandboxState
	PID              int
	Image            string
	Runtime          string
	Secrets          string
	SecretCount      int
	RW               bool
	Net              bool
	Shares           int
	MemMB            uint
	VCPUs            int
	Dir              string
	ConfigPath       string
	Updated          time.Time
	ConfigError      bool
	TXBytes          uint64
	RXBytes          uint64
	DroppedPackets   uint64
	TrafficAvailable bool
}

type tuiTrafficRow struct {
	Sandbox   string
	Host      string
	Address   string
	Protocol  string
	Port      uint16
	Allowed   bool
	TXBytes   uint64
	RXBytes   uint64
	TXPackets uint64
	RXPackets uint64
	FirstSeen time.Time
	LastSeen  time.Time
}

type tuiRuleRow struct {
	Sandbox string
	Action  string
	Target  string
	Proto   string
	Ports   string
	Source  string
	Policy  string
	Error   bool
}

type tuiMountRow struct {
	Sandbox  string
	Tag      string
	Host     string
	VM       string
	Guest    string
	ReadOnly bool
	State    string
	Error    string
}

type tuiDialog uint8

const (
	tuiNoDialog tuiDialog = iota
	tuiHelpDialog
	tuiInfoDialog
	tuiRemoveDialog
	tuiCreateDialog
	tuiShareAddDialog
	tuiShareRemoveDialog
)

type tuiToastKind uint8

const (
	tuiToastInfo tuiToastKind = iota
	tuiToastSuccess
	tuiToastWarning
	tuiToastError
)

type tuiToast struct {
	kind  tuiToastKind
	title string
	body  string
	gen   uint64
}

type tuiRefreshMsg struct {
	sandboxes []tuiSandbox
	traffic   []tuiTrafficRow
	rules     []tuiRuleRow
	mounts    []tuiMountRow
	err       error
	at        time.Time
}

type tuiTickMsg struct{}

type tuiProcessDoneMsg struct {
	action string
	name   string
	output string
	err    error
}

type tuiToastExpiredMsg struct{ gen uint64 }

type sandboxTUIModel struct {
	page      tuiPage
	sandboxes []tuiSandbox
	cursor    int // len(sandboxes) is the trailing "New Sandbox" card
	scrollRow int

	traffic       []tuiTrafficRow
	trafficCursor int
	trafficScroll int
	rules         []tuiRuleRow
	rulesCursor   int
	rulesScroll   int
	mounts        []tuiMountRow
	mountCursor   int
	mountScroll   int

	width  int
	height int
	dark   bool

	loading        bool
	refreshing     bool
	refreshVisible bool
	lastUpdate     time.Time
	busyAction     string
	busyName       string
	selectNext     string

	spinner   spinner.Model
	animating bool
	toast     *tuiToast
	toastGen  uint64

	dialog        tuiDialog
	confirmRemove bool
	createFocus   int
	createName    textinput.Model
	createImage   textinput.Model
	createRuntime string   // "crun" (default) or "runsc"
	createKernels []string // staged kernel paths; index 0 in the UI is "auto"
	createKernel  int
	shareFocus    int
	shareTag      textinput.Model
	sharePath     textinput.Model
	shareRO       bool
	shareReplace  bool
	formError     string

	lastClickIndex int
	lastClickAt    time.Time
}

func newSandboxTUIModel() sandboxTUIModel {
	sp := spinner.New(spinner.WithSpinner(spinner.MiniDot))
	name := textinput.New()
	name.Placeholder = "my-sandbox"
	name.CharLimit = 64
	name.Prompt = ""
	image := textinput.New()
	image.Placeholder = "blank uses Gantry's configured default"
	image.Prompt = ""
	shareTag := textinput.New()
	shareTag.Placeholder = "code"
	shareTag.CharLimit = 36
	shareTag.Prompt = ""
	sharePath := textinput.New()
	sharePath.Placeholder = "/absolute/host/path"
	sharePath.CharLimit = 4096
	sharePath.Prompt = ""

	m := sandboxTUIModel{
		width:          100,
		height:         30,
		dark:           true,
		loading:        true,
		refreshing:     true,
		spinner:        sp,
		animating:      true,
		createName:     name,
		createImage:    image,
		createRuntime:  "crun",
		shareTag:       shareTag,
		sharePath:      sharePath,
		shareRO:        true,
		lastClickIndex: -1,
	}
	m.applyInputTheme()
	return m
}

func (m sandboxTUIModel) Init() tea.Cmd {
	return tea.Batch(
		refreshSandboxesCmd(),
		tuiTickCmd(),
		m.spinner.Tick,
		func() tea.Msg { return tea.RequestBackgroundColor() },
	)
}

func (m *sandboxTUIModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.resizeInputs()
		m.ensureCursorVisible()
		return m, nil
	case tea.BackgroundColorMsg:
		m.dark = msg.IsDark()
		m.applyInputTheme()
		return m, nil
	case tea.FocusMsg:
		if !m.refreshing && m.busyAction == "" {
			m.refreshing = true
			return m, refreshSandboxesCmd()
		}
		return m, nil
	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		if m.needsAnimation() {
			m.animating = true
			return m, cmd
		}
		m.animating = false
		return m, nil
	case tuiRefreshMsg:
		return m.handleRefresh(msg)
	case tuiTickMsg:
		cmds := []tea.Cmd{tuiTickCmd()}
		if !m.refreshing && m.busyAction == "" {
			m.refreshing = true
			cmds = append(cmds, refreshSandboxesCmd())
		}
		return m, tea.Batch(cmds...)
	case tuiProcessDoneMsg:
		return m.handleProcessDone(msg)
	case tuiToastExpiredMsg:
		if m.toast != nil && m.toast.gen == msg.gen {
			m.toast = nil
		}
		return m, nil
	case tea.KeyPressMsg:
		return m.updateKey(msg)
	case tea.MouseClickMsg:
		return m.updateMouseClick(msg.Mouse())
	case tea.MouseWheelMsg:
		return m.updateMouseWheel(msg.Mouse())
	}
	return m, nil
}

func (m *sandboxTUIModel) handleRefresh(msg tuiRefreshMsg) (tea.Model, tea.Cmd) {
	wasLoading := m.loading
	m.loading = false
	m.refreshing = false
	m.refreshVisible = false
	m.lastUpdate = msg.at
	m.lastClickAt = time.Time{}
	if msg.err != nil {
		return m, m.showToast(tuiToastError, "Refresh failed", msg.err.Error())
	}

	selectedName := ""
	selectedNewCard := !wasLoading && m.onNewCard()
	if selected := m.selected(); selected != nil {
		selectedName = selected.Name
	}
	trafficKey, ruleKey, mountKey := m.selectedTableKeys()
	m.sandboxes = msg.sandboxes
	m.traffic = msg.traffic
	m.rules = msg.rules
	m.mounts = msg.mounts

	target := m.selectNext
	if target == "" {
		target = selectedName
	}
	found := false
	if target != "" {
		for i := range m.sandboxes {
			if m.sandboxes[i].Name == target {
				m.cursor = i
				found = true
				break
			}
		}
	}
	// A refresh that was already in flight can race a create process. Keep the
	// requested selection until the sandbox appears; handleProcessDone clears
	// it explicitly if creation fails.
	if found {
		m.selectNext = ""
	}
	if !found && selectedNewCard {
		m.cursor = len(m.sandboxes)
	} else if !found && m.cursor > len(m.sandboxes) {
		m.cursor = len(m.sandboxes)
	}
	m.restoreTableSelections(trafficKey, ruleKey, mountKey)
	m.ensureCursorVisible()
	m.ensureTableCursorVisible()
	return m, m.ensureAnimation()
}

func (m *sandboxTUIModel) handleProcessDone(msg tuiProcessDoneMsg) (tea.Model, tea.Cmd) {
	m.busyAction = ""
	m.busyName = ""
	m.refreshing = true

	kind, title, body := tuiToastSuccess, actionPastTense(msg.action), msg.name
	if msg.err != nil {
		kind = tuiToastError
		title = actionTitle(msg.action) + " failed"
		body = compactCommandError(msg.output, msg.err)
		m.selectNext = ""
	} else if msg.action == "open" {
		// An interactive command that exits non-zero is useful information, but
		// it should not make the dashboard itself look broken.
		if msg.output != "" {
			kind, body = tuiToastWarning, strings.TrimSpace(msg.output)
		} else {
			body = "Returned from " + msg.name
		}
	}
	return m, tea.Batch(refreshSandboxesCmd(), m.showToast(kind, title, body))
}

func (m *sandboxTUIModel) updateKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	if m.dialog != tuiNoDialog {
		return m.updateDialogKey(msg)
	}
	if m.busyAction != "" {
		switch msg.String() {
		case "?":
			m.dialog = tuiHelpDialog
		case "1":
			m.setPage(tuiSandboxesPage)
		case "2":
			m.setPage(tuiTrafficPage)
		case "3":
			m.setPage(tuiRulesPage)
		case "4":
			m.setPage(tuiMountsPage)
		case "tab", "]":
			m.cyclePage(1)
		case "shift+tab", "[":
			m.cyclePage(-1)
		case "ctrl+c":
			return m, func() tea.Msg { return tea.Quit() }
		}
		return m, nil
	}

	key := msg.String()
	if m.page == tuiMountsPage {
		switch key {
		case "a":
			return m, m.openShareAddDialog(false)
		case "d", "delete", "x":
			if m.selectedMount() != nil {
				m.dialog = tuiShareRemoveDialog
				m.confirmRemove = false
			}
			return m, nil
		case "r":
			return m, m.openShareAddDialog(true)
		case "R":
			if !m.refreshing {
				m.refreshing = true
				m.refreshVisible = true
				return m, tea.Batch(refreshSandboxesCmd(), m.ensureAnimation())
			}
			return m, nil
		}
	}
	switch key {
	case "q", "ctrl+c":
		return m, func() tea.Msg { return tea.Quit() }
	case "?":
		m.dialog = tuiHelpDialog
		return m, nil
	case "1":
		m.setPage(tuiSandboxesPage)
		return m, nil
	case "2":
		m.setPage(tuiTrafficPage)
		return m, nil
	case "3":
		m.setPage(tuiRulesPage)
		return m, nil
	case "4":
		m.setPage(tuiMountsPage)
		return m, nil
	case "tab", "]":
		m.cyclePage(1)
		return m, nil
	case "shift+tab", "[":
		m.cyclePage(-1)
		return m, nil
	case "r":
		if !m.refreshing {
			m.refreshing = true
			m.refreshVisible = true
			return m, tea.Batch(refreshSandboxesCmd(), m.ensureAnimation())
		}
		return m, nil
	}

	if m.page != tuiSandboxesPage {
		switch key {
		case "esc":
			m.setPage(tuiSandboxesPage)
		case "left", "h":
			m.cyclePage(-1)
		case "right", "l":
			m.cyclePage(1)
		case "up", "k":
			m.moveTableCursor(-1)
		case "down", "j":
			m.moveTableCursor(1)
		case "pgup":
			m.moveTableCursor(-m.tableVisibleRows())
		case "pgdown":
			m.moveTableCursor(m.tableVisibleRows())
		case "home", "g":
			cursor, _, _ := m.tableState()
			if cursor != nil {
				*cursor = 0
				m.ensureTableCursorVisible()
			}
		case "end", "G":
			cursor, _, count := m.tableState()
			if cursor != nil && count > 0 {
				*cursor = count - 1
				m.ensureTableCursorVisible()
			}
		}
		return m, nil
	}

	switch key {
	case "n":
		return m, m.openCreateDialog()
	case "left", "h":
		m.moveCursor(-1, 0)
	case "right", "l":
		m.moveCursor(1, 0)
	case "up", "k":
		m.moveCursor(0, -1)
	case "down", "j":
		m.moveCursor(0, 1)
	case "home", "g":
		m.setCursor(0)
	case "end", "G":
		m.setCursor(m.entryCount() - 1)
	case "pgup":
		m.pageCursor(-1)
	case "pgdown":
		m.pageCursor(1)
	case "enter", "o":
		return m.primaryAction()
	case "s":
		return m.toggleSelected()
	case "i":
		if m.selected() != nil {
			m.dialog = tuiInfoDialog
		}
	case "d", "delete", "x":
		if selected := m.selected(); selected != nil {
			m.dialog = tuiRemoveDialog
			m.confirmRemove = false
		}
	}
	return m, nil
}

func (m *sandboxTUIModel) primaryAction() (tea.Model, tea.Cmd) {
	if m.onNewCard() {
		return m, m.openCreateDialog()
	}
	selected := m.selected()
	if selected == nil {
		return m, nil
	}
	if selected.State == tuiRunning {
		return m.beginAction("open", selected.Name, []string{"exec", selected.Name}, true)
	}
	if selected.State == tuiStarting {
		return m, m.showToast(tuiToastInfo, "Sandbox is starting", selected.Name)
	}
	return m.beginAction("start", selected.Name, []string{"resume", selected.Name}, false)
}

func (m *sandboxTUIModel) toggleSelected() (tea.Model, tea.Cmd) {
	selected := m.selected()
	if selected == nil {
		return m, nil
	}
	switch selected.State {
	case tuiRunning:
		return m.beginAction("stop", selected.Name, []string{"stop", selected.Name}, false)
	case tuiStarting:
		return m, m.showToast(tuiToastInfo, "Sandbox is starting", selected.Name)
	default:
		return m.beginAction("start", selected.Name, []string{"resume", selected.Name}, false)
	}
}

func (m *sandboxTUIModel) beginAction(action, name string, argv []string, interactive bool) (tea.Model, tea.Cmd) {
	m.dialog = tuiNoDialog
	m.busyAction = action
	m.busyName = name
	if action == "create" || action == "start" {
		m.selectNext = name
	}
	return m, tea.Batch(runTUIProcessCmd(action, name, argv, interactive), m.ensureAnimation())
}

func runTUIProcessCmd(action, name string, argv []string, interactive bool) tea.Cmd {
	exe, err := os.Executable()
	if err != nil {
		return func() tea.Msg { return tuiProcessDoneMsg{action: action, name: name, err: err} }
	}
	cmd := exec.Command(exe, argv...)
	if interactive {
		return tea.ExecProcess(cmd, func(err error) tea.Msg {
			msg := tuiProcessDoneMsg{action: action, name: name}
			if err != nil {
				msg.output = err.Error()
				// Preserve the session's exit status as a warning rather than an
				// action failure; the TUI and terminal handoff both succeeded.
				if _, ok := err.(*exec.ExitError); !ok {
					msg.err = err
				}
			}
			return msg
		})
	}
	return func() tea.Msg {
		output, err := cmd.CombinedOutput()
		return tuiProcessDoneMsg{
			action: action,
			name:   name,
			output: strings.TrimSpace(string(output)),
			err:    err,
		}
	}
}

func (m *sandboxTUIModel) needsAnimation() bool {
	if m.loading || m.refreshVisible || m.busyAction != "" {
		return true
	}
	for _, sandbox := range m.sandboxes {
		if sandbox.State == tuiStarting {
			return true
		}
	}
	return false
}

func (m *sandboxTUIModel) ensureAnimation() tea.Cmd {
	if m.animating || !m.needsAnimation() {
		return nil
	}
	m.animating = true
	return m.spinner.Tick
}

func (m *sandboxTUIModel) showToast(kind tuiToastKind, title, body string) tea.Cmd {
	m.toastGen++
	gen := m.toastGen
	m.toast = &tuiToast{
		kind: kind, title: safeUILine(title), body: strings.TrimSpace(safeUIBlock(body)), gen: gen,
	}
	return tea.Tick(4*time.Second, func(time.Time) tea.Msg { return tuiToastExpiredMsg{gen: gen} })
}

func (m *sandboxTUIModel) selected() *tuiSandbox {
	if m.cursor < 0 || m.cursor >= len(m.sandboxes) {
		return nil
	}
	return &m.sandboxes[m.cursor]
}

func (m *sandboxTUIModel) selectedMount() *tuiMountRow {
	if m.mountCursor < 0 || m.mountCursor >= len(m.mounts) {
		return nil
	}
	return &m.mounts[m.mountCursor]
}

func (m *sandboxTUIModel) shareTargetSandbox() *tuiSandbox {
	if selected := m.selected(); selected != nil && selected.State == tuiRunning {
		return selected
	}
	for i := range m.sandboxes {
		if m.sandboxes[i].State == tuiRunning {
			return &m.sandboxes[i]
		}
	}
	return nil
}

func (m *sandboxTUIModel) onNewCard() bool { return m.cursor == len(m.sandboxes) }
func (m *sandboxTUIModel) entryCount() int { return len(m.sandboxes) + 1 }

func (m *sandboxTUIModel) setCursor(index int) {
	m.cursor = clampInt(index, 0, m.entryCount()-1)
	m.ensureCursorVisible()
}

func (m *sandboxTUIModel) moveCursor(dx, dy int) {
	layout := m.dashboardLayout()
	if dx != 0 {
		row := m.cursor / layout.cols
		candidate := m.cursor + dx
		if candidate >= 0 && candidate < m.entryCount() && candidate/layout.cols == row {
			m.cursor = candidate
		}
	}
	if dy != 0 {
		candidate := m.cursor + dy*layout.cols
		if candidate < 0 {
			candidate = 0
		}
		if candidate >= m.entryCount() {
			lastRowStart := ((m.entryCount() - 1) / layout.cols) * layout.cols
			candidate = minInt(m.entryCount()-1, lastRowStart+(m.cursor%layout.cols))
		}
		m.cursor = candidate
	}
	m.ensureCursorVisible()
}

func (m *sandboxTUIModel) pageCursor(direction int) {
	layout := m.dashboardLayout()
	step := maxInt(1, layout.visibleRows*layout.cols)
	m.setCursor(m.cursor + direction*step)
}

func (m *sandboxTUIModel) ensureCursorVisible() {
	layout := m.dashboardLayout()
	row := m.cursor / layout.cols
	if row < m.scrollRow {
		m.scrollRow = row
	}
	if row >= m.scrollRow+layout.visibleRows {
		m.scrollRow = row - layout.visibleRows + 1
	}
	m.scrollRow = clampInt(m.scrollRow, 0, layout.maxScrollRow(m.entryCount()))
}

func (m *sandboxTUIModel) setPage(page tuiPage) {
	if page >= tuiPageCount {
		return
	}
	m.page = page
	m.ensureTableCursorVisible()
}

func (m *sandboxTUIModel) cyclePage(delta int) {
	page := (int(m.page) + delta + int(tuiPageCount)) % int(tuiPageCount)
	m.setPage(tuiPage(page))
}

func (m *sandboxTUIModel) tableState() (cursor, scroll *int, count int) {
	switch m.page {
	case tuiTrafficPage:
		return &m.trafficCursor, &m.trafficScroll, len(m.traffic)
	case tuiRulesPage:
		return &m.rulesCursor, &m.rulesScroll, len(m.rules)
	case tuiMountsPage:
		return &m.mountCursor, &m.mountScroll, len(m.mounts)
	default:
		return nil, nil, 0
	}
}

func (m *sandboxTUIModel) moveTableCursor(delta int) {
	cursor, _, count := m.tableState()
	if cursor == nil || count == 0 {
		return
	}
	*cursor = clampInt(*cursor+delta, 0, count-1)
	m.ensureTableCursorVisible()
}

func (m *sandboxTUIModel) ensureTableCursorVisible() {
	cursor, scroll, count := m.tableState()
	if cursor == nil {
		return
	}
	if count == 0 {
		*cursor, *scroll = 0, 0
		return
	}
	*cursor = clampInt(*cursor, 0, count-1)
	visible := m.tableVisibleRows()
	if *cursor < *scroll {
		*scroll = *cursor
	}
	if *cursor >= *scroll+visible {
		*scroll = *cursor - visible + 1
	}
	*scroll = clampInt(*scroll, 0, maxInt(0, count-visible))
}

func (m sandboxTUIModel) selectedTableKeys() (traffic, rule, mount string) {
	if m.trafficCursor >= 0 && m.trafficCursor < len(m.traffic) {
		traffic = trafficRowKey(m.traffic[m.trafficCursor])
	}
	if m.rulesCursor >= 0 && m.rulesCursor < len(m.rules) {
		rule = ruleRowKey(m.rules[m.rulesCursor])
	}
	if m.mountCursor >= 0 && m.mountCursor < len(m.mounts) {
		mount = mountRowKey(m.mounts[m.mountCursor])
	}
	return
}

func (m *sandboxTUIModel) restoreTableSelections(traffic, rule, mount string) {
	for i := range m.traffic {
		if traffic != "" && trafficRowKey(m.traffic[i]) == traffic {
			m.trafficCursor = i
			break
		}
	}
	for i := range m.rules {
		if rule != "" && ruleRowKey(m.rules[i]) == rule {
			m.rulesCursor = i
			break
		}
	}
	for i := range m.mounts {
		if mount != "" && mountRowKey(m.mounts[i]) == mount {
			m.mountCursor = i
			break
		}
	}
	m.trafficCursor = clampTableCursor(m.trafficCursor, len(m.traffic))
	m.rulesCursor = clampTableCursor(m.rulesCursor, len(m.rules))
	m.mountCursor = clampTableCursor(m.mountCursor, len(m.mounts))
}

func trafficRowKey(row tuiTrafficRow) string {
	return fmt.Sprintf("%s\x00%s\x00%s\x00%d\x00%t", row.Sandbox, row.Address, row.Protocol, row.Port, row.Allowed)
}

func ruleRowKey(row tuiRuleRow) string {
	return strings.Join([]string{row.Sandbox, row.Action, row.Target, row.Proto, row.Ports, row.Source}, "\x00")
}

func mountRowKey(row tuiMountRow) string {
	return strings.Join([]string{row.Sandbox, row.Tag, row.Host, row.Guest}, "\x00")
}

func clampTableCursor(cursor, count int) int {
	if count == 0 {
		return 0
	}
	return clampInt(cursor, 0, count-1)
}

func refreshSandboxesCmd() tea.Cmd {
	return func() tea.Msg {
		data, err := loadTUIData()
		return tuiRefreshMsg{
			sandboxes: data.sandboxes, traffic: data.traffic,
			rules: data.rules, mounts: data.mounts, err: err, at: time.Now(),
		}
	}
}

func tuiTickCmd() tea.Cmd {
	return tea.Tick(2*time.Second, func(time.Time) tea.Msg { return tuiTickMsg{} })
}

type tuiData struct {
	sandboxes []tuiSandbox
	traffic   []tuiTrafficRow
	rules     []tuiRuleRow
	mounts    []tuiMountRow
}

func loadTUISandboxes() ([]tuiSandbox, error) {
	data, err := loadTUIData()
	return data.sandboxes, err
}

func loadTUIData() (tuiData, error) {
	entries, err := os.ReadDir(sandboxRoot())
	if os.IsNotExist(err) {
		return tuiData{}, nil
	}
	if err != nil {
		return tuiData{}, err
	}

	data := tuiData{sandboxes: make([]tuiSandbox, 0, len(entries))}
	for _, entry := range entries {
		if !entry.IsDir() || !validSandboxName(entry.Name()) {
			continue
		}
		name := entry.Name()
		dir := sandboxDir(name)
		sandbox := tuiSandbox{
			Name: name, State: tuiStopped, Image: "unknown", Runtime: "crun",
			Secrets: "none", MemMB: 512, VCPUs: 1, Dir: dir,
			ConfigPath: filepath.Join(dir, "sandbox.json"),
		}
		if pid, alive := sandboxPID(name); alive {
			sandbox.PID = pid
			sandbox.State = tuiStarting
			if fileExists(filepath.Join(dir, "ready")) {
				sandbox.State = tuiRunning
			}
		}
		if info, statErr := os.Stat(sandbox.ConfigPath); statErr == nil {
			sandbox.Updated = info.ModTime()
		}

		var cfg RunConfig
		configOK := false
		if raw, readErr := os.ReadFile(sandbox.ConfigPath); readErr == nil && json.Unmarshal(raw, &cfg) == nil {
			configOK = true
			sandbox.Image = safeUILine(cfg.ImageRef)
			if sandbox.Image == "" {
				sandbox.Image = safeUILine(filepath.Base(cfg.Image))
			}
			if sandbox.Image == "" {
				sandbox.Image = "unknown"
			}
			if cfg.Runtime != "" {
				sandbox.Runtime = safeUILine(cfg.Runtime)
			}
			sandbox.RW, sandbox.Net, sandbox.Shares = cfg.RW, cfg.Net, len(cfg.Shares)
			if cfg.MemMB > 0 {
				sandbox.MemMB = cfg.MemMB
			}
			if cfg.VCPUs > 0 {
				sandbox.VCPUs = cfg.VCPUs
			}
			sandbox.SecretCount = len(cfg.SecretNames)
			if sandbox.SecretCount > 0 {
				secretNames := make([]string, 0, sandbox.SecretCount)
				for _, secretName := range cfg.SecretNames {
					secretNames = append(secretNames, safeUILine(secretName))
				}
				sandbox.Secrets = strings.Join(secretNames, ", ")
			}
		} else {
			sandbox.ConfigError = true
			data.rules = append(data.rules, tuiRuleRow{Sandbox: name, Action: "error", Target: "sandbox configuration unavailable", Proto: "—", Source: "sandbox.json", Error: true})
			data.mounts = append(data.mounts, tuiMountRow{Sandbox: name, Tag: "invalid", Error: "sandbox configuration unavailable"})
		}

		trafficPath := filepath.Join(dir, netpol.TrafficFileName)
		sandbox.TrafficAvailable = fileExists(trafficPath)
		traffic, trafficErr := netpol.ReadTrafficSnapshot(trafficPath)
		if trafficErr == nil {
			sandbox.TXBytes, sandbox.RXBytes = traffic.TXBytes, traffic.RXBytes
			sandbox.DroppedPackets = traffic.DroppedPackets
			var classifiedDroppedBytes, classifiedDroppedPackets uint64
			for _, entry := range traffic.Entries {
				if !entry.Allowed {
					classifiedDroppedBytes += entry.TXBytes
					classifiedDroppedPackets += entry.TXPackets
				}
				data.traffic = append(data.traffic, tuiTrafficRow{
					Sandbox: name, Host: safeUILine(entry.Host), Address: safeUILine(entry.Address),
					Protocol: safeUILine(entry.Protocol), Port: entry.Port, Allowed: entry.Allowed,
					TXBytes: entry.TXBytes, RXBytes: entry.RXBytes,
					TXPackets: entry.TXPackets, RXPackets: entry.RXPackets,
					FirstSeen: entry.FirstSeen, LastSeen: entry.LastSeen,
				})
			}
			if traffic.DroppedPackets > classifiedDroppedPackets {
				data.traffic = append(data.traffic, tuiTrafficRow{
					Sandbox: name, Host: "unclassified traffic", Address: "non-IP / historical",
					Protocol: "other", Allowed: false,
					TXBytes:   traffic.DroppedBytes - minUint64(traffic.DroppedBytes, classifiedDroppedBytes),
					TXPackets: traffic.DroppedPackets - classifiedDroppedPackets,
					LastSeen:  traffic.Updated,
				})
			}
		}
		if configOK {
			data.rules = append(data.rules, loadTUIRules(name, cfg)...)
			mountRows, live := loadTUIMounts(name, cfg, sandbox.State == tuiRunning)
			data.mounts = append(data.mounts, mountRows...)
			if live {
				sandbox.Shares = len(mountRows)
			}
		}
		data.sandboxes = append(data.sandboxes, sandbox)
	}

	sort.Slice(data.sandboxes, func(i, j int) bool {
		left, right := strings.ToLower(data.sandboxes[i].Name), strings.ToLower(data.sandboxes[j].Name)
		if left == right {
			return data.sandboxes[i].Name < data.sandboxes[j].Name
		}
		return left < right
	})
	sort.SliceStable(data.traffic, func(i, j int) bool { return data.traffic[i].LastSeen.After(data.traffic[j].LastSeen) })
	sort.SliceStable(data.rules, func(i, j int) bool { return data.rules[i].Sandbox < data.rules[j].Sandbox })
	sort.SliceStable(data.mounts, func(i, j int) bool {
		if data.mounts[i].Sandbox == data.mounts[j].Sandbox {
			return data.mounts[i].Tag < data.mounts[j].Tag
		}
		return data.mounts[i].Sandbox < data.mounts[j].Sandbox
	})
	return data, nil
}

func loadTUIRules(sandbox string, cfg RunConfig) []tuiRuleRow {
	if !cfg.Net {
		return []tuiRuleRow{{Sandbox: sandbox, Action: "off", Target: "network disabled", Proto: "—", Source: "config"}}
	}
	if cfg.GVProxy != "" {
		return []tuiRuleRow{{Sandbox: sandbox, Action: "allow", Target: "all destinations", Proto: "any", Source: "external gvproxy", Policy: safeUILine(cfg.GVProxy)}}
	}
	policy := netpol.DefaultPolicy()
	policyPath := "built-in default"
	if cfg.NetPol != "" {
		loaded, err := netpol.Load(cfg.NetPol)
		if err != nil {
			return []tuiRuleRow{{Sandbox: sandbox, Action: "error", Target: safeUILine(err.Error()), Proto: "—", Source: "policy", Policy: cfg.NetPol, Error: true}}
		}
		policy, policyPath = loaded, cfg.NetPol
	}
	if cfg.AllowLN {
		policy.AllowLocal = true
	}
	summaries := policy.RuleSummaries()
	rows := make([]tuiRuleRow, 0, len(summaries))
	for _, summary := range summaries {
		rows = append(rows, tuiRuleRow{
			Sandbox: sandbox, Action: summary.Action, Target: safeUILine(summary.Target),
			Proto: summary.Protocol, Ports: summary.Ports, Source: summary.Source,
			Policy: safeUILine(policyPath),
		})
	}
	return rows
}

func loadTUIMounts(sandbox string, cfg RunConfig, running bool) ([]tuiMountRow, bool) {
	if running {
		if raw, err := os.ReadFile(filepath.Join(sandboxDir(sandbox), "shares.json")); err == nil {
			var manifest shares.Manifest
			if json.Unmarshal(raw, &manifest) == nil && manifest.Transport != nil {
				rows := make([]tuiMountRow, 0, len(manifest.Shares))
				for _, entry := range manifest.Shares {
					row := tuiMountRow{
						Sandbox: sandbox, Tag: safeUILine(entry.Tag), Host: safeUILine(entry.Path),
						VM: safeUILine(entry.VMPath), Guest: safeUILine(entry.CtrPath),
						ReadOnly: entry.RO, State: safeUILine(defaultShareState(entry.State)),
					}
					if row.State == "error" {
						row.Error = "share backend error"
					}
					rows = append(rows, row)
				}
				return rows, true
			}
		} else if !os.IsNotExist(err) {
			return []tuiMountRow{{Sandbox: sandbox, Tag: "invalid", Error: safeUILine(err.Error())}}, true
		}
	}
	parsed, err := cfg.ParsedShares()
	if err != nil {
		return []tuiMountRow{{Sandbox: sandbox, Tag: "invalid", Error: safeUILine(err.Error())}}, false
	}
	rows := make([]tuiMountRow, 0, len(parsed))
	for _, share := range parsed {
		guest := share.CtrPath
		if guest == "" {
			guest = shares.HubHostPath + "/" + share.Tag
		}
		rows = append(rows, tuiMountRow{
			Sandbox: sandbox, Tag: safeUILine(share.Tag), Host: safeUILine(share.Path),
			VM: shares.HubVMPath + "/" + safeUILine(share.Tag), Guest: safeUILine(guest),
			ReadOnly: share.RO, State: "saved",
		})
	}
	return rows, false
}

func compactCommandError(output string, err error) string {
	output = strings.TrimSpace(output)
	if output == "" {
		return err.Error()
	}
	lines := strings.Split(output, "\n")
	if len(lines) > 3 {
		lines = lines[len(lines)-3:]
	}
	return strings.Join(lines, "\n")
}

func actionTitle(action string) string {
	switch action {
	case "create":
		return "Create sandbox"
	case "start":
		return "Start sandbox"
	case "stop":
		return "Stop sandbox"
	case "delete":
		return "Remove sandbox"
	case "open":
		return "Open sandbox"
	case "share add":
		return "Add share"
	case "share replace":
		return "Replace share"
	case "share remove":
		return "Remove share"
	default:
		return strings.Title(action) //nolint:staticcheck // action names are ASCII UI labels.
	}
}

func actionPastTense(action string) string {
	switch action {
	case "create":
		return "Sandbox created"
	case "start":
		return "Sandbox started"
	case "stop":
		return "Sandbox stopped"
	case "delete":
		return "Sandbox removed"
	case "open":
		return "Session closed"
	case "share add":
		return "Share added"
	case "share replace":
		return "Share replaced"
	case "share remove":
		return "Share removed"
	default:
		return actionTitle(action) + " complete"
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func clampInt(value, low, high int) int {
	if value < low {
		return low
	}
	if value > high {
		return high
	}
	return value
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func minUint64(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}
