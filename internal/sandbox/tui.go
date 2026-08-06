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
	"gantry/internal/vmm"

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
	tuiPortsPage
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
	GVProxy          string
	NetPolicy        string
	AllowLocal       bool
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
	UID      *uint32
	GID      *uint32
	State    string
	Error    string
}

type tuiPortRow struct {
	Sandbox string
	Bind    string // host bind, e.g. "127.0.0.1:8080"
	Guest   int
	Proto   string
	State   string // "bound" | "saved"
	Error   string
}

type tuiDialog uint8

const (
	tuiNoDialog tuiDialog = iota
	tuiHelpDialog
	tuiInfoDialog
	tuiRemoveDialog
	tuiCreateDialog
	tuiEditDialog
	tuiShareAddDialog
	tuiShareRemoveDialog
	tuiPortPublishDialog
	tuiPortUnpublishDialog
	tuiNetworkPolicyDialog
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
	ports     []tuiPortRow
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
	ports         []tuiPortRow
	portCursor    int
	portScroll    int

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
	createCPUs    resourceSlider
	createMemory  resourceSlider
	createRuntime string   // "crun" (default) or "runsc"
	createKernels []string // staged kernel paths; index 0 in the UI is "auto"
	createKernel  int
	editFocus     int
	editCPUs      resourceSlider
	editMemory    resourceSlider
	shareFocus    int
	shareSandbox  sandboxPicker
	shareTag      textinput.Model
	sharePath     textinput.Model
	shareMount    textinput.Model
	shareOwner    textinput.Model
	shareRO       bool
	shareReplace  bool
	portFocus     int
	portSandbox   sandboxPicker
	portBind      textinput.Model
	portGuest     textinput.Model
	portUDP       bool
	policyFocus   int
	policySandbox sandboxPicker
	policyPath    textinput.Model
	policyLocal   bool
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
	createCPUs := newResourceSlider(1, maxSandboxVCPUs, 1, 1)
	createMemory := newResourceSlider(128, 65536, 128, 512)
	editCPUs := newResourceSlider(1, maxSandboxVCPUs, 1, 1)
	editMemory := newResourceSlider(128, 65536, 128, 512)
	shareTag := textinput.New()
	shareTag.Placeholder = "code"
	shareTag.CharLimit = 36
	shareTag.Prompt = ""
	sharePath := textinput.New()
	sharePath.Placeholder = "/absolute/host/path"
	sharePath.CharLimit = 4096
	sharePath.Prompt = ""
	shareMount := textinput.New()
	shareMount.Placeholder = "/host/<tag> (default)"
	shareMount.CharLimit = 4096
	shareMount.Prompt = ""
	shareOwner := textinput.New()
	shareOwner.Placeholder = "host (or UID:GID, e.g. 1000:1000)"
	shareOwner.CharLimit = 32
	shareOwner.Prompt = ""
	portBind := textinput.New()
	portBind.Placeholder = "8080 (blank = auto, ip:port to widen)"
	portBind.CharLimit = 64
	portBind.Prompt = ""
	portGuest := textinput.New()
	portGuest.Placeholder = "80"
	portGuest.CharLimit = 8
	portGuest.Prompt = ""
	policyPath := textinput.New()
	policyPath.Placeholder = "blank uses the built-in default"
	policyPath.CharLimit = 4096
	policyPath.Prompt = ""

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
		createCPUs:     createCPUs,
		createMemory:   createMemory,
		createRuntime:  "crun",
		editCPUs:       editCPUs,
		editMemory:     editMemory,
		shareTag:       shareTag,
		sharePath:      sharePath,
		shareMount:     shareMount,
		shareOwner:     shareOwner,
		shareRO:        true,
		portBind:       portBind,
		portGuest:      portGuest,
		policyPath:     policyPath,
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
	trafficKey, ruleKey, mountKey, portKey := m.selectedTableKeys()
	m.sandboxes = msg.sandboxes
	m.traffic = msg.traffic
	m.rules = msg.rules
	m.mounts = msg.mounts
	m.ports = msg.ports

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
	m.restoreTableSelections(trafficKey, ruleKey, mountKey, portKey)
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
	} else if (msg.action == "edit" || msg.action == "share configure" || msg.action == "netpolicy set") && msg.output != "" {
		body = strings.TrimSpace(msg.output)
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
		case "5":
			m.setPage(tuiPortsPage)
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
	if m.page == tuiRulesPage {
		switch key {
		case "e", "p":
			return m, m.openNetworkPolicyDialog()
		}
	}
	if m.page == tuiPortsPage {
		switch key {
		case "p", "a":
			return m, m.openPortPublishDialog()
		case "d", "delete", "x", "u":
			if m.selectedPort() != nil {
				m.dialog = tuiPortUnpublishDialog
				m.confirmRemove = false
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
	case "5":
		m.setPage(tuiPortsPage)
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
	case "e":
		return m, m.openEditDialog()
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

func saveSandboxResourcesCmd(name string, memMB uint, vcpus int, running bool) tea.Cmd {
	return func() tea.Msg {
		err := setSandboxResources(name, memMB, vcpus)
		body := fmt.Sprintf("%d CPU · %d MiB RAM", vcpus, memMB)
		if running {
			body += " · restart to apply"
		} else {
			body += " · applies on next start"
		}
		return tuiProcessDoneMsg{action: "edit", name: name, output: body, err: err}
	}
}

func setSandboxNetworkPolicyCmd(name, path string, allowLocal bool) tea.Cmd {
	return func() tea.Msg {
		entry, err := setSandboxNetworkPolicy(name, path, allowLocal)
		body := entry.Description
		if entry.Path == "" {
			body = "built-in default · " + body
		}
		return tuiProcessDoneMsg{action: "netpolicy set", name: name, output: body, err: err}
	}
}

func configureSandboxShareCmd(name, tag, spec, mountpoint string, replace bool) tea.Cmd {
	return func() tea.Msg {
		err := configureSandboxShare(name, spec, replace)
		body := fmt.Sprintf("%s → %s · restart to apply", tag, mountpoint)
		return tuiProcessDoneMsg{action: "share configure", name: name + "/" + tag, output: body, err: err}
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

func (m *sandboxTUIModel) selectedPort() *tuiPortRow {
	if m.portCursor < 0 || m.portCursor >= len(m.ports) {
		return nil
	}
	return &m.ports[m.portCursor]
}

func (m *sandboxTUIModel) selectedRule() *tuiRuleRow {
	if m.rulesCursor < 0 || m.rulesCursor >= len(m.rules) {
		return nil
	}
	return &m.rules[m.rulesCursor]
}

func (m *sandboxTUIModel) sandboxNamed(name string) *tuiSandbox {
	for i := range m.sandboxes {
		if m.sandboxes[i].Name == name {
			return &m.sandboxes[i]
		}
	}
	return nil
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
	case tuiPortsPage:
		return &m.portCursor, &m.portScroll, len(m.ports)
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

func (m sandboxTUIModel) selectedTableKeys() (traffic, rule, mount, port string) {
	if m.trafficCursor >= 0 && m.trafficCursor < len(m.traffic) {
		traffic = trafficRowKey(m.traffic[m.trafficCursor])
	}
	if m.rulesCursor >= 0 && m.rulesCursor < len(m.rules) {
		rule = ruleRowKey(m.rules[m.rulesCursor])
	}
	if m.mountCursor >= 0 && m.mountCursor < len(m.mounts) {
		mount = mountRowKey(m.mounts[m.mountCursor])
	}
	if m.portCursor >= 0 && m.portCursor < len(m.ports) {
		port = portRowKey(m.ports[m.portCursor])
	}
	return
}

func (m *sandboxTUIModel) restoreTableSelections(traffic, rule, mount, port string) {
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
	for i := range m.ports {
		if port != "" && portRowKey(m.ports[i]) == port {
			m.portCursor = i
			break
		}
	}
	m.trafficCursor = clampTableCursor(m.trafficCursor, len(m.traffic))
	m.rulesCursor = clampTableCursor(m.rulesCursor, len(m.rules))
	m.mountCursor = clampTableCursor(m.mountCursor, len(m.mounts))
	m.portCursor = clampTableCursor(m.portCursor, len(m.ports))
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

func portRowKey(row tuiPortRow) string {
	return strings.Join([]string{row.Sandbox, row.Bind, row.Proto}, "\x00")
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
			rules: data.rules, mounts: data.mounts, ports: data.ports, err: err, at: time.Now(),
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
	ports     []tuiPortRow
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
			sandbox.GVProxy = safeUILine(cfg.GVProxy)
			sandbox.NetPolicy = safeUILine(cfg.NetPol)
			sandbox.AllowLocal = cfg.AllowLN
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
			data.ports = append(data.ports, loadTUIPorts(name, cfg, sandbox.State == tuiRunning)...)
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
	sort.SliceStable(data.ports, func(i, j int) bool {
		if data.ports[i].Sandbox == data.ports[j].Sandbox {
			return data.ports[i].Bind < data.ports[j].Bind
		}
		return data.ports[i].Sandbox < data.ports[j].Sandbox
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
	parsed, parseErr := cfg.ParsedShares()
	rowForConfigured := func(share vmm.Share, state string) tuiMountRow {
		guest := configuredShareTarget(share)
		return tuiMountRow{
			Sandbox: sandbox, Tag: safeUILine(share.Tag), Host: safeUILine(share.Path),
			VM: shares.HubVMPath + "/" + safeUILine(share.Tag), Guest: safeUILine(guest),
			ReadOnly: share.RO, UID: share.UID, GID: share.GID, State: state,
		}
	}
	if running {
		if raw, err := os.ReadFile(filepath.Join(sandboxDir(sandbox), "shares.json")); err == nil {
			var manifest shares.Manifest
			if json.Unmarshal(raw, &manifest) == nil && manifest.Transport != nil {
				rows := make([]tuiMountRow, 0, len(manifest.Shares))
				for _, entry := range manifest.Shares {
					row := tuiMountRow{
						Sandbox: sandbox, Tag: safeUILine(entry.Tag), Host: safeUILine(entry.Path),
						VM: safeUILine(entry.VMPath), Guest: safeUILine(entry.CtrPath),
						ReadOnly: entry.RO, UID: entry.UID, GID: entry.GID,
						State: safeUILine(defaultShareState(entry.State)),
					}
					if row.State == "error" {
						row.Error = "share backend error"
					}
					rows = append(rows, row)
				}
				if parseErr != nil {
					rows = append(rows, tuiMountRow{Sandbox: sandbox, Tag: "invalid", Error: safeUILine(parseErr.Error())})
					return rows, true
				}
				liveByTag := make(map[string]int, len(rows))
				for i := range rows {
					liveByTag[rows[i].Tag] = i
				}
				for _, configured := range parsed {
					desired := rowForConfigured(configured, "restart")
					if index, ok := liveByTag[desired.Tag]; ok {
						if tuiMountRowsEqual(rows[index], desired) {
							continue
						}
						// A live error state is health information, not drift:
						// keep it instead of clobbering the row with "restart".
						if rows[index].State == "error" {
							desired.State, desired.Error = rows[index].State, rows[index].Error
						}
						rows[index] = desired
						continue
					}
					rows = append(rows, desired)
				}
				return rows, true
			}
		} else if !os.IsNotExist(err) {
			return []tuiMountRow{{Sandbox: sandbox, Tag: "invalid", Error: safeUILine(err.Error())}}, true
		}
	}
	if parseErr != nil {
		return []tuiMountRow{{Sandbox: sandbox, Tag: "invalid", Error: safeUILine(parseErr.Error())}}, false
	}
	rows := make([]tuiMountRow, 0, len(parsed))
	for _, share := range parsed {
		rows = append(rows, rowForConfigured(share, "saved"))
	}
	return rows, false
}

func tuiMountRowsEqual(a, b tuiMountRow) bool {
	return a.Tag == b.Tag && a.Host == b.Host && a.Guest == b.Guest && a.ReadOnly == b.ReadOnly &&
		optionalUint32Equal(a.UID, b.UID) && optionalUint32Equal(a.GID, b.GID)
}

func optionalUint32Equal(a, b *uint32) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

// loadTUIPorts reads the publish set for one sandbox: the live bound/saved
// merge from the running daemon's broker, else the desired specs persisted
// in sandbox.json (state "saved").
func loadTUIPorts(sandbox string, cfg RunConfig, running bool) []tuiPortRow {
	rowFor := func(mapping PortMapping, state string) tuiPortRow {
		return tuiPortRow{
			Sandbox: sandbox,
			Bind:    safeUILine(mapping.Local()),
			Guest:   int(mapping.GuestPort),
			Proto:   mapping.Proto,
			State:   state,
		}
	}
	if running {
		resp, err := portControlRPC(sandbox, "port.list", brokerPortRequest{Persistent: true})
		if err != nil {
			return []tuiPortRow{{Sandbox: sandbox, Bind: "unavailable", Error: safeUILine(err.Error())}}
		}
		rows := make([]tuiPortRow, 0, len(resp.Ports))
		for _, entry := range resp.Ports {
			rows = append(rows, rowFor(entry.Mapping, entry.State))
		}
		return rows
	}
	rows := make([]tuiPortRow, 0, len(cfg.Ports))
	for _, spec := range cfg.Ports {
		mapping, err := ParsePortSpec(spec)
		if err != nil {
			rows = append(rows, tuiPortRow{Sandbox: sandbox, Bind: "invalid", Error: safeUILine(err.Error())})
			continue
		}
		rows = append(rows, rowFor(mapping, "saved"))
	}
	return rows
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
	case "share configure":
		return "Save share"
	case "port publish":
		return "Publish port"
	case "port unpublish":
		return "Unpublish port"
	case "edit":
		return "Edit sandbox"
	case "netpolicy set":
		return "Apply network policy"
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
	case "share configure":
		return "Share saved"
	case "port publish":
		return "Port published"
	case "port unpublish":
		return "Port unpublished"
	case "edit":
		return "Sandbox updated"
	case "netpolicy set":
		return "Network policy applied"
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
