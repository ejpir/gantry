package dashboard

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	dashboardapi "github.com/ejpir/gantry/internal/dashboard/api"
	"github.com/ejpir/gantry/internal/secret"
	"github.com/ejpir/gantry/internal/selfupdate"

	"charm.land/bubbles/v2/spinner"
	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"golang.org/x/term"
)

// Run starts Gantry's local sandbox dashboard.
func Run(service dashboardapi.Service) int {
	if !term.IsTerminal(int(os.Stdin.Fd())) || !term.IsTerminal(int(os.Stdout.Fd())) {
		fmt.Fprintln(os.Stderr, "gantry tui: requires an interactive terminal")
		return 2
	}

	model := newSandboxTUIModel(service)
	program := tea.NewProgram(
		&model,
		tea.WithInput(os.Stdin),
		tea.WithOutput(os.Stdout),
	)
	final, err := program.Run()
	if err != nil {
		fmt.Fprintln(os.Stderr, "gantry tui:", err)
		return 1
	}
	if result, ok := final.(*sandboxTUIModel); ok && result.exitMessage != "" {
		fmt.Fprintln(os.Stderr, result.exitMessage)
	}
	return 0
}

const (
	tuiStopped  = dashboardapi.Stopped
	tuiStarting = dashboardapi.Starting
	tuiRunning  = dashboardapi.Running
)

type tuiPage uint8

const (
	tuiSandboxesPage tuiPage = iota
	tuiTrafficPage
	tuiRulesPage
	tuiMountsPage
	tuiPortsPage
	tuiSecretsPage
	tuiMCPPage
	tuiPacketsPage
	tuiImagesPage
	tuiOverviewPage
	tuiPageCount
)

type tuiSandbox = dashboardapi.Sandbox
type tuiTrafficRow = dashboardapi.Traffic
type tuiRuleRow = dashboardapi.Rule
type tuiMountRow = dashboardapi.Mount
type tuiPortRow = dashboardapi.Port
type tuiSecretRow = dashboardapi.Secret
type tuiMCPRow = dashboardapi.MCPServer
type tuiImageRow = dashboardapi.Image
type tuiRegistryRow = dashboardapi.RegistryAuth

// Images page sections: one page manages both the cached image store and
// the registry credentials used to pull into it.
const (
	tuiImageSectionImages      = "images"
	tuiImageSectionCredentials = "credentials"
)

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
	tuiRuleAddDialog
	tuiRuleRemoveDialog
	tuiSecretAddDialog
	tuiSecretRemoveDialog
	tuiMCPRemoteDialog
	tuiMCPFilesystemDialog
	tuiMCPRemoveDialog
	tuiUpdateDialog
	tuiPacketDetailDialog
	tuiImagePullDialog
	tuiImageRemoveDialog
	tuiImagePruneDialog
	tuiRegistryLoginDialog
	tuiRegistryLogoutDialog
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
	sandboxes  []tuiSandbox
	traffic    []tuiTrafficRow
	rules      []tuiRuleRow
	mounts     []tuiMountRow
	ports      []tuiPortRow
	secrets    []tuiSecretRow
	mcp        []tuiMCPRow
	images     []tuiImageRow
	registries []tuiRegistryRow
	err        error
	at         time.Time
}

type tuiTickMsg struct{}

type tuiPacketPollMsg struct{}

type tuiProcessDoneMsg struct {
	action string
	name   string
	output string
	err    error
}

type tuiProcessStreamEvent struct {
	progress string
	done     *tuiProcessDoneMsg
}

type tuiProcessStreamMsg struct {
	event  tuiProcessStreamEvent
	stream <-chan tuiProcessStreamEvent
}

type tuiClipboardMsg struct {
	label string
	err   error
}

type tuiToastExpiredMsg struct{ gen uint64 }

type tuiUpdateStatusMsg struct {
	status selfupdate.Status
	err    error
	live   bool
}

type sandboxTUIModel struct {
	service dashboardapi.Service
	limits  dashboardapi.ResourceLimits

	page      tuiPage
	sandboxes []tuiSandbox
	cursor    int // len(sandboxes) is the trailing "New Sandbox" card
	scrollRow int

	traffic        []tuiTrafficRow
	trafficCursor  int
	trafficScroll  int
	rules          []tuiRuleRow
	rulesCursor    int
	rulesScroll    int
	mounts         []tuiMountRow
	mountCursor    int
	mountScroll    int
	ports          []tuiPortRow
	portCursor     int
	portScroll     int
	secrets        []tuiSecretRow
	secretCursor   int
	secretScroll   int
	mcpServers     []tuiMCPRow
	mcpCursor      int
	mcpScroll      int
	images         []tuiImageRow
	imageCursor    int
	imageScroll    int
	registries     []tuiRegistryRow
	registryCursor int
	registryScroll int
	imageSection   string
	packets        []tuiPacketRow
	packetCursor   int
	packetScroll   int
	packetAfter    map[string]uint64
	packetLoading  bool
	packetPaused   bool
	packetError    string
	packetEvicted  uint64
	packetDetail   *tuiPacketRow

	width  int
	height int
	dark   bool

	loading        bool
	refreshing     bool
	refreshVisible bool
	lastUpdate     time.Time
	busyAction     string
	busyName       string
	busyProgress   string
	selectNext     string

	spinner   spinner.Model
	animating bool
	toast     *tuiToast
	toastGen  uint64

	updateStatus  selfupdate.Status
	updateChecked bool
	exitMessage   string

	dialog              tuiDialog
	dialogScroll        int
	confirmRemove       bool
	createFocus         int
	createErrFocus      int
	createName          textinput.Model
	createImage         textinput.Model
	createCPUs          resourceSlider
	createMemory        resourceSlider
	createDisk          resourceSlider
	createRuntime       string   // "crun" (default) or "runsc"
	createKernels       []string // staged kernel paths; index 0 in the UI is "auto"
	createKernel        int
	createIsolation     string
	createSSH           bool
	createDevContainers bool
	editFocus           int
	editCPUs            resourceSlider
	editMemory          resourceSlider
	editIsolation       string
	editSSH             bool
	editDevContainers   bool
	shareFocus          int
	shareSandbox        sandboxPicker
	shareTag            textinput.Model
	sharePath           textinput.Model
	shareMount          textinput.Model
	shareOwner          textinput.Model
	shareRO             bool
	shareReplace        bool
	portFocus           int
	portSandbox         sandboxPicker
	portBind            textinput.Model
	portGuest           textinput.Model
	portUDP             bool
	policyFocus         int
	policySandbox       sandboxPicker
	policyPath          textinput.Model
	policyLocal         bool
	ruleFocus           int
	ruleSandbox         sandboxPicker
	ruleTarget          textinput.Model
	rulePorts           textinput.Model
	ruleAction          string
	ruleProtocol        string
	secretFocus         int
	secretSandbox       sandboxPicker
	secretName          textinput.Model
	secretValue         textinput.Model
	mcpFocus            int
	mcpSandbox          sandboxPicker
	mcpName             textinput.Model
	mcpURL              textinput.Model
	mcpAuthKind         string
	mcpAuthHeader       textinput.Model
	mcpAuthRef          textinput.Model
	mcpAllow            textinput.Model
	mcpDeny             textinput.Model
	mcpRedact           textinput.Model
	mcpEditing          bool
	mcpFSFocus          int
	mcpFSRoot           textinput.Model
	mcpFSUser           textinput.Model
	pullFocus           int
	pullRef             textinput.Model
	pullArch            string
	loginFocus          int
	loginRegistry       textinput.Model
	loginUsername       textinput.Model
	loginPassword       textinput.Model
	formError           string

	lastClickIndex int
	lastClickAt    time.Time

	// dashboardHits is emitted by the last render pass. Mouse events consume
	// this map instead of independently reconstructing component positions.
	dashboardHits  []tuiHitTarget
	trafficHistory map[string][]uint64
	trafficTotals  map[string]uint64
}

func newSandboxTUIModel(service dashboardapi.Service) sandboxTUIModel {
	limits := service.ResourceLimits()
	sp := spinner.New(spinner.WithSpinner(spinner.MiniDot))
	name := textinput.New()
	name.Placeholder = "my-sandbox"
	name.CharLimit = 64
	name.Prompt = ""
	image := textinput.New()
	image.Placeholder = "blank uses Gantry's configured default"
	image.Prompt = ""
	createCPUs := newResourceSlider(1, limits.MaxVCPUs, 1, 1)
	createMemory := newResourceSlider(int(limits.MinMemoryMB), int(limits.MaxMemoryMB), 128, 512)
	createDisk := newResourceSlider(int(limits.MinDiskSizeMiB), int(limits.MaxDiskSizeMiB), 512, int(limits.DefaultDiskSizeMiB))
	editCPUs := newResourceSlider(1, limits.MaxVCPUs, 1, 1)
	editMemory := newResourceSlider(int(limits.MinMemoryMB), int(limits.MaxMemoryMB), 128, 512)
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
	ruleTarget := textinput.New()
	ruleTarget.Placeholder = "203.0.113.10 or 203.0.113.0/24 (blank = all)"
	ruleTarget.CharLimit = 64
	ruleTarget.Prompt = ""
	rulePorts := textinput.New()
	rulePorts.Placeholder = "443 or 8000-9000 (blank = any)"
	rulePorts.CharLimit = 128
	rulePorts.Prompt = ""
	secretName := textinput.New()
	secretName.Placeholder = "GITHUB_TOKEN"
	secretName.CharLimit = 128
	secretName.Prompt = ""
	secretValue := textinput.New()
	secretValue.Placeholder = "value is never displayed or persisted"
	secretValue.CharLimit = 1 << 20
	secretValue.Prompt = ""
	secretValue.EchoMode = textinput.EchoPassword
	secretValue.EchoCharacter = '•'
	mcpName := textinput.New()
	mcpName.Placeholder = "github"
	mcpName.CharLimit = 31
	mcpName.Prompt = ""
	mcpURL := textinput.New()
	mcpURL.Placeholder = "https://example.com/mcp"
	mcpURL.CharLimit = 4096
	mcpURL.Prompt = ""
	mcpAuthHeader := textinput.New()
	mcpAuthHeader.Placeholder = "X-Api-Key"
	mcpAuthHeader.CharLimit = 64
	mcpAuthHeader.Prompt = ""
	mcpAuthRef := textinput.New()
	mcpAuthRef.Placeholder = "secret name"
	mcpAuthRef.CharLimit = 128
	mcpAuthRef.Prompt = ""
	mcpAllow := textinput.New()
	mcpAllow.Placeholder = "* (comma-separated globs; blank denies all)"
	mcpAllow.CharLimit = 4096
	mcpAllow.Prompt = ""
	mcpDeny := textinput.New()
	mcpDeny.Placeholder = "delete_*,admin_*"
	mcpDeny.CharLimit = 4096
	mcpDeny.Prompt = ""
	mcpRedact := textinput.New()
	mcpRedact.Placeholder = "OTHER_SECRET,SECOND_SECRET"
	mcpRedact.CharLimit = 4096
	mcpRedact.Prompt = ""
	mcpFSRoot := textinput.New()
	mcpFSRoot.Placeholder = "/workspace"
	mcpFSRoot.CharLimit = 4096
	mcpFSRoot.Prompt = ""
	mcpFSUser := textinput.New()
	mcpFSUser.Placeholder = "nobody or 1000:1000"
	mcpFSUser.CharLimit = 128
	mcpFSUser.Prompt = ""
	pullRef := textinput.New()
	pullRef.Placeholder = "debian:bookworm-slim or ghcr.io/org/app:latest"
	pullRef.CharLimit = 512
	pullRef.Prompt = ""
	loginRegistry := textinput.New()
	loginRegistry.Placeholder = "ghcr.io"
	loginRegistry.CharLimit = 253
	loginRegistry.Prompt = ""
	loginUsername := textinput.New()
	loginUsername.Placeholder = "username"
	loginUsername.CharLimit = 256
	loginUsername.Prompt = ""
	loginPassword := textinput.New()
	loginPassword.Placeholder = "password or token — never displayed again"
	loginPassword.CharLimit = 1 << 20
	loginPassword.Prompt = ""
	loginPassword.EchoMode = textinput.EchoPassword
	loginPassword.EchoCharacter = '•'

	m := sandboxTUIModel{
		service:         service,
		page:            tuiOverviewPage,
		limits:          limits,
		width:           100,
		height:          30,
		dark:            true,
		loading:         true,
		refreshing:      true,
		spinner:         sp,
		animating:       true,
		createErrFocus:  -1,
		createName:      name,
		createImage:     image,
		createCPUs:      createCPUs,
		createMemory:    createMemory,
		createDisk:      createDisk,
		createRuntime:   "crun",
		createIsolation: "auto",
		editCPUs:        editCPUs,
		editMemory:      editMemory,
		shareTag:        shareTag,
		sharePath:       sharePath,
		shareMount:      shareMount,
		shareOwner:      shareOwner,
		shareRO:         true,
		portBind:        portBind,
		portGuest:       portGuest,
		policyPath:      policyPath,
		ruleTarget:      ruleTarget,
		rulePorts:       rulePorts,
		ruleAction:      "deny",
		ruleProtocol:    "tcp",
		secretName:      secretName,
		secretValue:     secretValue,
		mcpName:         mcpName,
		mcpURL:          mcpURL,
		mcpAuthHeader:   mcpAuthHeader,
		mcpAuthRef:      mcpAuthRef,
		mcpAllow:        mcpAllow,
		mcpDeny:         mcpDeny,
		mcpRedact:       mcpRedact,
		mcpFSRoot:       mcpFSRoot,
		mcpFSUser:       mcpFSUser,
		pullRef:         pullRef,
		pullArch:        "auto",
		loginRegistry:   loginRegistry,
		loginUsername:   loginUsername,
		loginPassword:   loginPassword,
		imageSection:    tuiImageSectionImages,
		lastClickIndex:  -1,
		packetAfter:     make(map[string]uint64),
		trafficHistory:  make(map[string][]uint64),
		trafficTotals:   make(map[string]uint64),
	}
	m.applyInputTheme()
	return m
}

func (m sandboxTUIModel) Init() tea.Cmd {
	return tea.Batch(
		refreshSandboxesCmd(m.service),
		cachedTUIUpdateCmd(),
		checkTUIUpdateCmd(),
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
		m.ensureDialogFocusVisible()
		return m, nil
	case tea.BackgroundColorMsg:
		m.dark = msg.IsDark()
		m.applyInputTheme()
		return m, nil
	case tea.FocusMsg:
		if !m.refreshing && m.busyAction == "" {
			m.refreshing = true
			return m, refreshSandboxesCmd(m.service)
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
			cmds = append(cmds, refreshSandboxesCmd(m.service))
		}
		return m, tea.Batch(cmds...)
	case tuiPacketPollMsg:
		if m.page == tuiPacketsPage && !m.packetPaused {
			return m, m.refreshPacketsCmd()
		}
		return m, nil
	case tuiPacketCaptureMsg:
		return m.handlePacketCapture(msg)
	case tuiProcessDoneMsg:
		return m.handleProcessDone(msg)
	case tuiProcessStreamMsg:
		if msg.event.done != nil {
			return m.handleProcessDone(*msg.event.done)
		}
		m.busyProgress = safeUILine(msg.event.progress)
		return m, waitTUIProcessStream(msg.stream)
	case tuiToastExpiredMsg:
		if m.toast != nil && m.toast.gen == msg.gen {
			m.toast = nil
		}
		return m, nil
	case tuiUpdateStatusMsg:
		if msg.err == nil && (msg.live || !m.updateChecked) {
			m.updateStatus = msg.status
		}
		if msg.live && msg.err == nil {
			m.updateChecked = true
		}
		return m, nil
	case tuiClipboardMsg:
		if msg.err != nil {
			return m, m.showToast(tuiToastError, "Clipboard unavailable", msg.err.Error())
		}
		return m, m.showToast(tuiToastSuccess, "Copied", msg.label)
	case tea.KeyPressMsg:
		return m.updateKey(msg)
	case tea.MouseClickMsg:
		return m.updateMouseClick(msg.Mouse())
	case tea.MouseWheelMsg:
		return m.updateMouseWheel(msg.Mouse())
	}
	if m.dialog != tuiNoDialog {
		return m.updateFocusedDialogInput(msg)
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
	trafficKey, ruleKey, mountKey, portKey, secretKey, mcpKey, imageKey, registryKey := m.selectedTableKeys()
	m.sampleSandboxTraffic(msg.sandboxes)
	m.sandboxes = msg.sandboxes
	m.traffic = msg.traffic
	m.rules = msg.rules
	m.mounts = msg.mounts
	m.ports = msg.ports
	m.secrets = msg.secrets
	m.mcpServers = msg.mcp
	m.images = msg.images
	m.registries = msg.registries

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
	m.restoreTableSelections(trafficKey, ruleKey, mountKey, portKey, secretKey, mcpKey, imageKey, registryKey)
	m.ensureCursorVisible()
	m.ensureTableCursorVisible()
	return m, m.ensureAnimation()
}

func (m *sandboxTUIModel) handleProcessDone(msg tuiProcessDoneMsg) (tea.Model, tea.Cmd) {
	m.busyAction = ""
	m.busyName = ""
	m.busyProgress = ""
	if msg.action == "update" {
		if msg.err != nil {
			return m, m.showToast(tuiToastError, "Update failed", compactCommandError(msg.output, msg.err))
		}
		m.updateStatus = selfupdate.Status{Current: m.updateStatus.Latest, Latest: m.updateStatus.Latest}
		m.exitMessage = lastOutputLine(msg.output)
		if m.exitMessage == "" {
			m.exitMessage = "Gantry updated. Restart the TUI to use the new release."
		}
		return m, tea.Quit
	}
	m.refreshing = true

	kind, title, body := tuiToastSuccess, actionPastTense(msg.action), msg.name
	if msg.err != nil {
		kind = tuiToastError
		title = actionTitle(msg.action) + " failed"
		body = compactCommandError(msg.output, msg.err)
		m.selectNext = ""
	} else if (msg.action == "edit" || msg.action == "share configure" || msg.action == "netpolicy set" || msg.action == "registry login" || msg.action == "image prune" || strings.HasPrefix(msg.action, "mcp ")) && msg.output != "" {
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
	return m, tea.Batch(refreshSandboxesCmd(m.service), m.showToast(kind, title, body))
}

func lastOutputLine(output string) string {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	for index := len(lines) - 1; index >= 0; index-- {
		if line := strings.TrimSpace(lines[index]); line != "" {
			return line
		}
	}
	return ""
}

func (m *sandboxTUIModel) updateKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	if m.dialog != tuiNoDialog {
		return m.updateDialogKey(msg)
	}
	key := msg.String()
	if m.busyAction != "" {
		return m, m.updateBusyKey(key)
	}
	if cmd, handled := m.updatePageActionKey(key); handled {
		return m, cmd
	}
	if cmd, handled := m.updateGlobalKey(key); handled {
		return m, cmd
	}
	if m.page == tuiOverviewPage {
		return m, m.updateOverviewKey(key)
	}
	if m.page != tuiSandboxesPage {
		m.updateTableKey(key)
		return m, nil
	}
	return m, m.updateSandboxKey(key)
}

func (m *sandboxTUIModel) updateBusyKey(key string) tea.Cmd {
	if key == "ctrl+c" {
		return tea.Quit
	}
	m.updatePageKey(key)
	return nil
}

func (m *sandboxTUIModel) updatePageActionKey(key string) (tea.Cmd, bool) {
	switch m.page {
	case tuiTrafficPage:
		switch key {
		case "a":
			row := m.selectedTraffic()
			if row == nil {
				return nil, true
			}
			if strings.EqualFold(row.Protocol, "dns") && row.Allowed {
				return m.showToast(tuiToastInfo, "DNS already allowed", "Only blocked DNS names can be added to allowDomains; remove exact entries from Rules."), true
			}
			if strings.EqualFold(row.Protocol, "dns") && (strings.TrimSpace(row.Host) == "" || row.Host == row.Address) {
				return m.showToast(tuiToastInfo, "DNS name unavailable", "This observation does not contain a queried domain to add to allowDomains."), true
			}
			return m.openRuleAddDialog(), true
		case "r":
			row := m.selectedTraffic()
			if row == nil {
				return nil, true
			}
			_, cmd := m.removeSelectedTrafficRule()
			return cmd, true
		case "R":
			return m.refreshCmd(), true
		}
	case tuiMountsPage:
		switch key {
		case "a":
			return m.openShareAddDialog(false), true
		case "d", "delete", "x":
			if m.selectedMount() != nil {
				m.dialog = tuiShareRemoveDialog
				m.dialogScroll = 0
				m.confirmRemove = false
			}
			return nil, true
		case "r":
			return m.openShareAddDialog(true), true
		case "R":
			return m.refreshCmd(), true
		}
	case tuiRulesPage:
		switch key {
		case "e", "p":
			return m.openNetworkPolicyDialog(), true
		case "d", "delete", "x":
			row := m.selectedRule()
			if row == nil {
				return nil, true
			}
			if removableRule(*row) {
				m.dialog = tuiRuleRemoveDialog
				m.dialogScroll = 0
				m.confirmRemove = false
				return nil, true
			}
			return m.showToast(
				tuiToastInfo,
				"Effective rule",
				"Built-in and default rows cannot be deleted. Press e to edit the network policy.",
			), true
		}
	case tuiPortsPage:
		switch key {
		case "p", "a":
			return m.openPortPublishDialog(), true
		case "d", "delete", "x", "u":
			if m.selectedPort() != nil {
				m.dialog = tuiPortUnpublishDialog
				m.dialogScroll = 0
				m.confirmRemove = false
			}
			return nil, true
		}
	case tuiSecretsPage:
		switch key {
		case "a":
			return m.openSecretAddDialog(), true
		case "d", "delete", "x":
			if m.selectedSecret() != nil {
				m.dialog = tuiSecretRemoveDialog
				m.dialogScroll = 0
				m.confirmRemove = false
			}
			return nil, true
		}
	case tuiMCPPage:
		switch key {
		case "a":
			return m.openMCPRemoteDialog(false), true
		case "f":
			return m.openMCPFilesystemDialog(), true
		case "e":
			row := m.selectedMCPServer()
			if row == nil {
				return nil, true
			}
			if row.Error != "" {
				return m.showToast(tuiToastInfo, "Invalid MCP configuration", row.Error), true
			}
			if row.Type == "local" {
				return m.openMCPFilesystemDialog(), true
			}
			return m.openMCPRemoteDialog(true), true
		case "d", "delete", "x":
			row := m.selectedMCPServer()
			if row == nil {
				return nil, true
			}
			if row.Type != "remote" || row.Error != "" {
				return m.showToast(tuiToastInfo, "Built-in MCP server", "The filesystem server can be edited but not removed."), true
			}
			m.dialog = tuiMCPRemoveDialog
			m.dialogScroll = 0
			m.confirmRemove = false
			return nil, true
		}
	case tuiImagesPage:
		switch key {
		case "s":
			m.switchImageSection()
			return nil, true
		}
		if m.imageSection == tuiImageSectionCredentials {
			switch key {
			case "a", "l":
				return m.openRegistryLoginDialog(), true
			case "d", "delete", "x":
				row := m.selectedRegistry()
				if row == nil {
					return nil, true
				}
				if !row.HasSecret {
					return m.showToast(tuiToastInfo, "Nothing stored", "No credential is stored for "+row.Registry+" — anonymous pulls use it as-is."), true
				}
				m.dialog = tuiRegistryLogoutDialog
				m.dialogScroll = 0
				m.confirmRemove = false
				return nil, true
			}
			return nil, false
		}
		switch key {
		case "p", "a":
			return m.openImagePullDialog(), true
		case "d", "delete", "x":
			if m.selectedImage() == nil {
				return nil, true
			}
			m.dialog = tuiImageRemoveDialog
			m.dialogScroll = 0
			m.confirmRemove = false
			return nil, true
		case "u":
			if m.prunableImageCount() == 0 {
				return m.showToast(tuiToastInfo, "Nothing to prune", "Every cached image is referenced by a sandbox."), true
			}
			m.dialog = tuiImagePruneDialog
			m.dialogScroll = 0
			m.confirmRemove = false
			return nil, true
		}
		return nil, false
	case tuiPacketsPage:
		return m.updatePacketActionKey(key)
	}
	return nil, false
}

func (m *sandboxTUIModel) updateGlobalKey(key string) (tea.Cmd, bool) {
	switch key {
	case "q", "ctrl+c":
		return tea.Quit, true
	case "n":
		return m.openCreateDialog(), true
	case "r":
		return m.refreshCmd(), true
	case "U":
		if m.updateStatus.Available {
			m.dialog = tuiUpdateDialog
			m.dialogScroll = 0
			m.confirmRemove = false
		}
		return nil, true
	}
	previous := m.page
	handled := m.updatePageKey(key)
	if handled && previous != tuiPacketsPage && m.page == tuiPacketsPage {
		return m.refreshPacketsCmd(), true
	}
	return nil, handled
}

var checkTUIUpdate = selfupdate.Refresh

func cachedTUIUpdateCmd() tea.Cmd {
	status, found, _ := selfupdate.Cached()
	if !found {
		return nil
	}
	return func() tea.Msg { return tuiUpdateStatusMsg{status: status} }
}

func checkTUIUpdateCmd() tea.Cmd {
	if !selfupdate.Enabled() {
		return nil
	}
	if _, _, fresh := selfupdate.Cached(); fresh {
		return nil
	}
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		status, err := checkTUIUpdate(ctx)
		return tuiUpdateStatusMsg{status: status, err: err, live: true}
	}
}

func (m *sandboxTUIModel) updatePageKey(key string) bool {
	switch key {
	case "?":
		m.dialog = tuiHelpDialog
		m.dialogScroll = 0
	case "0":
		m.setPage(tuiOverviewPage)
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
	case "6":
		m.setPage(tuiSecretsPage)
	case "7":
		m.setPage(tuiMCPPage)
	case "8":
		m.setPage(tuiPacketsPage)
	case "9":
		m.setPage(tuiImagesPage)
	case "tab", "]":
		m.cyclePage(1)
	case "shift+tab", "[":
		m.cyclePage(-1)
	default:
		return false
	}
	return true
}

func (m *sandboxTUIModel) refreshCmd() tea.Cmd {
	if m.refreshing {
		return nil
	}
	m.refreshing = true
	m.refreshVisible = true
	return tea.Batch(refreshSandboxesCmd(m.service), m.ensureAnimation())
}

func (m *sandboxTUIModel) updateTableKey(key string) {
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
		m.moveTableCursorToBoundary(false)
	case "end", "G":
		m.moveTableCursorToBoundary(true)
	}
}

func (m *sandboxTUIModel) moveTableCursorToBoundary(end bool) {
	cursor, _, count := m.tableState()
	if cursor == nil || count == 0 {
		return
	}
	*cursor = 0
	if end {
		*cursor = count - 1
	}
	m.ensureTableCursorVisible()
}

func (m *sandboxTUIModel) updateOverviewKey(key string) tea.Cmd {
	switch key {
	case "up", "k", "left", "h":
		m.setCursor(m.cursor - 1)
	case "down", "j", "right", "l":
		m.setCursor(m.cursor + 1)
	case "home", "g":
		m.setCursor(0)
	case "end", "G":
		m.setCursor(len(m.sandboxes) - 1)
	case "enter", "o":
		if len(m.sandboxes) == 0 {
			return m.openCreateDialog()
		}
		m.setPage(tuiSandboxesPage)
	case "t":
		selected := m.selected()
		m.setPage(tuiTrafficPage)
		if selected != nil {
			for index, row := range m.traffic {
				if row.Sandbox == selected.Name {
					m.trafficCursor = index
					m.ensureTableCursorVisible()
					break
				}
			}
		}
	case "s":
		_, cmd := m.toggleSelected()
		return cmd
	case "e":
		return m.openEditDialog()
	case "i":
		if m.selected() != nil {
			m.dialog = tuiInfoDialog
			m.dialogScroll = 0
		}
	case "d", "delete", "x":
		if m.selected() != nil {
			m.dialog = tuiRemoveDialog
			m.dialogScroll = 0
			m.confirmRemove = false
		}
	}
	return nil
}

func (m *sandboxTUIModel) updateSandboxKey(key string) tea.Cmd {
	masterDetail := m.usesMasterDetail(m.dashboardLayout())
	switch key {
	case "left", "h":
		if !masterDetail {
			m.moveCursor(-1, 0)
		}
	case "right", "l":
		if !masterDetail {
			m.moveCursor(1, 0)
		}
	case "up", "k":
		if masterDetail {
			m.setCursor(m.cursor - 1)
		} else {
			m.moveCursor(0, -1)
		}
	case "down", "j":
		if masterDetail {
			m.setCursor(m.cursor + 1)
		} else {
			m.moveCursor(0, 1)
		}
	case "home", "g":
		m.setCursor(0)
	case "end", "G":
		m.setCursor(m.entryCount() - 1)
	case "pgup":
		m.pageCursor(-1)
	case "pgdown":
		m.pageCursor(1)
	case "enter", "o":
		_, cmd := m.primaryAction()
		return cmd
	case "s":
		_, cmd := m.toggleSelected()
		return cmd
	case "i":
		if m.selected() != nil {
			m.dialog = tuiInfoDialog
			m.dialogScroll = 0
		}
	case "e":
		return m.openEditDialog()
	case "d", "delete", "x":
		if m.selected() != nil {
			m.dialog = tuiRemoveDialog
			m.dialogScroll = 0
			m.confirmRemove = false
		}
	}
	return nil
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
	m.dialogScroll = 0
	m.busyAction = action
	m.busyName = name
	m.busyProgress = ""
	if action == "create" || action == "start" {
		m.selectNext = name
	}
	return m, tea.Batch(runTUIProcessCmd(m.service, action, name, argv, interactive), m.ensureAnimation())
}

func runTUIProcessCmd(service dashboardapi.Service, action, name string, argv []string, interactive bool) tea.Cmd {
	cmd, err := service.Command(argv...)
	if err != nil {
		return func() tea.Msg { return tuiProcessDoneMsg{action: action, name: name, err: err} }
	}
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
	events := make(chan tuiProcessStreamEvent, 16)
	return func() tea.Msg {
		output := &tuiProcessOutput{events: events}
		cmd.Stdout = output
		cmd.Stderr = output
		go func() {
			err := cmd.Run()
			events <- tuiProcessStreamEvent{done: &tuiProcessDoneMsg{
				action: action,
				name:   name,
				output: strings.TrimSpace(output.String()),
				err:    err,
			}}
			close(events)
		}()
		return receiveTUIProcessStream(events)
	}
}

func waitTUIProcessStream(stream <-chan tuiProcessStreamEvent) tea.Cmd {
	return func() tea.Msg { return receiveTUIProcessStream(stream) }
}

func receiveTUIProcessStream(stream <-chan tuiProcessStreamEvent) tea.Msg {
	event, ok := <-stream
	if !ok {
		done := tuiProcessDoneMsg{err: fmt.Errorf("process output stream closed unexpectedly")}
		event.done = &done
	}
	return tuiProcessStreamMsg{event: event, stream: stream}
}

// tuiProcessOutput retains the command's complete diagnostic output while
// forwarding only bounded operation-progress lines to Bubble Tea. stdout and
// stderr may be copied concurrently by os/exec, hence the shared lock.
type tuiProcessOutput struct {
	mu      sync.Mutex
	output  bytes.Buffer
	pending string
	events  chan<- tuiProcessStreamEvent
}

func (w *tuiProcessOutput) Write(p []byte) (int, error) {
	w.mu.Lock()
	_, _ = w.output.Write(p)
	w.pending += string(p)
	var progress []string
	for {
		newline := strings.IndexByte(w.pending, '\n')
		if newline < 0 {
			break
		}
		line := strings.TrimSuffix(w.pending[:newline], "\r")
		w.pending = w.pending[newline+1:]
		if line, ok := operationProgressLine(line); ok {
			progress = append(progress, line)
		}
	}
	w.mu.Unlock()

	for _, line := range progress {
		select {
		case w.events <- tuiProcessStreamEvent{progress: line}:
		default: // The next update supersedes a stale intermediate percentage.
		}
	}
	return len(p), nil
}

func (w *tuiProcessOutput) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.output.String()
}

func operationProgressLine(line string) (string, bool) {
	start := -1
	for _, marker := range []string{"downloading ", "creating persistent disk "} {
		if index := strings.Index(line, marker); index >= 0 && (start < 0 || index < start) {
			start = index
		}
	}
	if start < 0 {
		// Image pulls report one line per layer instead of a progress bar.
		// The CLI prefixes those with "gantry image: "; its failure line is
		// "gantry image <verb>: " (no space before the colon), so the two
		// never collide.
		if index := strings.Index(line, "gantry image: "); index >= 0 {
			progress := strings.TrimSpace(line[index+len("gantry image: "):])
			return progress, progress != ""
		}
		return "", false
	}
	line = line[start:]
	if !strings.Contains(line, "[") || !strings.Contains(line, "]") {
		return "", false
	}
	return line, true
}

func saveSandboxConfigCmd(service dashboardapi.Service, request dashboardapi.SandboxConfigRequest, running bool) tea.Cmd {
	return func() tea.Msg {
		restart, err := service.ConfigureSandbox(request)
		state := func(enabled bool) string {
			if enabled {
				return "on"
			}
			return "off"
		}
		body := fmt.Sprintf("SSH %s · Dev Containers %s · %d CPU · %d MiB RAM · isolation %s",
			state(request.SSH), state(request.DevContainers), request.VCPUs, request.MemMB, request.ProcessIsolation)
		if restart && running {
			body += " · restart to apply resource changes"
		} else if !running {
			body += " · applies on next start"
		}
		return tuiProcessDoneMsg{action: "edit", name: request.Name, output: body, err: err}
	}
}

func addNetworkRuleCmd(service dashboardapi.Service, request dashboardapi.RuleRequest) tea.Cmd {
	return func() tea.Msg {
		err := service.AddNetworkRule(request)
		return tuiProcessDoneMsg{action: "rule add", name: request.Sandbox, err: err}
	}
}

func removeNetworkRuleCmd(service dashboardapi.Service, row tuiRuleRow) tea.Cmd {
	return func() tea.Msg {
		err := service.RemoveNetworkRule(row)
		return tuiProcessDoneMsg{action: "rule remove", name: row.Sandbox + "/" + row.Source, err: err}
	}
}

func removeTrafficRuleCmd(service dashboardapi.Service, row tuiTrafficRow) tea.Cmd {
	return func() tea.Msg {
		err := service.RemoveTrafficRule(row)
		return tuiProcessDoneMsg{action: "rule remove", name: row.Sandbox + "/" + row.Address, err: err}
	}
}

func addSecretCmd(service dashboardapi.Service, request dashboardapi.SecretRequest) tea.Cmd {
	return func() tea.Msg {
		err := service.AddSecret(request)
		request.Value = secret.Value("")
		return tuiProcessDoneMsg{action: "secret add", name: request.Sandbox + "/" + request.Name, err: err}
	}
}

func removeSecretCmd(service dashboardapi.Service, row tuiSecretRow) tea.Cmd {
	return func() tea.Msg {
		err := service.RemoveSecret(row)
		return tuiProcessDoneMsg{action: "secret remove", name: row.Sandbox + "/" + row.Name, err: err}
	}
}

func removeImageCmd(service dashboardapi.Service, row tuiImageRow) tea.Cmd {
	return func() tea.Msg {
		err := service.RemoveImage(row.Ref)
		return tuiProcessDoneMsg{action: "image remove", name: row.Ref, err: err}
	}
}

func pruneImagesCmd(service dashboardapi.Service) tea.Cmd {
	return func() tea.Msg {
		count, err := service.PruneImages()
		body := fmt.Sprintf("%d unused images removed", count)
		if count == 1 {
			body = "1 unused image removed"
		}
		return tuiProcessDoneMsg{action: "image prune", name: "", output: body, err: err}
	}
}

// storeRegistryLoginCmd persists a credential and scrubs the request's secret
// before the result message crosses the Bubble Tea boundary.
func storeRegistryLoginCmd(service dashboardapi.Service, request dashboardapi.RegistryLoginRequest) tea.Cmd {
	return func() tea.Msg {
		warning, err := service.StoreRegistryLogin(request)
		request.Secret = secret.Value("")
		msg := tuiProcessDoneMsg{action: "registry login", name: request.Registry, err: err}
		if err == nil && warning != "" {
			msg.output = warning
		}
		return msg
	}
}

func removeRegistryLoginCmd(service dashboardapi.Service, row tuiRegistryRow) tea.Cmd {
	return func() tea.Msg {
		err := service.RemoveRegistryLogin(row.Registry)
		return tuiProcessDoneMsg{action: "registry logout", name: row.Registry, err: err}
	}
}

func configureMCPRemoteCmd(service dashboardapi.Service, request dashboardapi.MCPRemoteRequest, running bool) tea.Cmd {
	return func() tea.Msg {
		err := service.ConfigureMCPRemote(request)
		apply := "applies on next start"
		if running {
			apply = "restart to apply"
		}
		return tuiProcessDoneMsg{action: "mcp configure", name: request.Sandbox + "/" + request.Name, output: apply, err: err}
	}
}

func configureMCPFilesystemCmd(service dashboardapi.Service, request dashboardapi.MCPFilesystemRequest, running bool) tea.Cmd {
	return func() tea.Msg {
		err := service.ConfigureMCPFilesystem(request)
		apply := "applies on next start"
		if running {
			apply = "restart to apply"
		}
		return tuiProcessDoneMsg{action: "mcp filesystem", name: request.Sandbox + "/fs", output: apply, err: err}
	}
}

func removeMCPRemoteCmd(service dashboardapi.Service, row tuiMCPRow, running bool) tea.Cmd {
	return func() tea.Msg {
		err := service.RemoveMCPRemote(row)
		apply := "removed for next start"
		if running {
			apply = "restart to withdraw the live server"
		}
		return tuiProcessDoneMsg{action: "mcp remove", name: row.Sandbox + "/" + row.Name, output: apply, err: err}
	}
}

func setSandboxNetworkPolicyCmd(service dashboardapi.Service, name, path string, allowLocal bool) tea.Cmd {
	return func() tea.Msg {
		entry, err := service.SetNetworkPolicy(name, path, allowLocal)
		body := entry.Description
		if entry.Path == "" {
			body = "built-in default · " + body
		}
		return tuiProcessDoneMsg{action: "netpolicy set", name: name, output: body, err: err}
	}
}

func configureSandboxShareCmd(service dashboardapi.Service, plan dashboardapi.SharePlan, running bool) tea.Cmd {
	return func() tea.Msg {
		err := service.ConfigureShare(plan)
		applyNote := "applies on next start"
		if running {
			applyNote = "restart to apply"
		}
		body := fmt.Sprintf("%s → %s · %s", plan.Tag, plan.Mountpoint, applyNote)
		return tuiProcessDoneMsg{action: "share configure", name: plan.Sandbox + "/" + plan.Tag, output: body, err: err}
	}
}

func removeSandboxShareCmd(service dashboardapi.Service, row tuiMountRow) tea.Cmd {
	return func() tea.Msg {
		err := service.RemoveShare(row)
		return tuiProcessDoneMsg{action: "share remove", name: row.Sandbox + "/" + row.Tag, err: err}
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

func (m *sandboxTUIModel) selectedTraffic() *tuiTrafficRow {
	if m.trafficCursor < 0 || m.trafficCursor >= len(m.traffic) {
		return nil
	}
	return &m.traffic[m.trafficCursor]
}

func (m *sandboxTUIModel) selectedSecret() *tuiSecretRow {
	if m.secretCursor < 0 || m.secretCursor >= len(m.secrets) {
		return nil
	}
	return &m.secrets[m.secretCursor]
}

func (m *sandboxTUIModel) selectedMCPServer() *tuiMCPRow {
	if m.mcpCursor < 0 || m.mcpCursor >= len(m.mcpServers) {
		return nil
	}
	return &m.mcpServers[m.mcpCursor]
}

func (m *sandboxTUIModel) selectedImage() *tuiImageRow {
	if m.imageCursor < 0 || m.imageCursor >= len(m.images) {
		return nil
	}
	return &m.images[m.imageCursor]
}

func (m *sandboxTUIModel) selectedRegistry() *tuiRegistryRow {
	if m.registryCursor < 0 || m.registryCursor >= len(m.registries) {
		return nil
	}
	return &m.registries[m.registryCursor]
}

func (m *sandboxTUIModel) switchImageSection() {
	if m.imageSection == tuiImageSectionImages {
		m.imageSection = tuiImageSectionCredentials
	} else {
		m.imageSection = tuiImageSectionImages
	}
	m.ensureTableCursorVisible()
}

func (m *sandboxTUIModel) prunableImageCount() int {
	count := 0
	for _, row := range m.images {
		if !row.InUse {
			count++
		}
	}
	return count
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
	if selected := m.selected(); selected != nil && selected.State != tuiStarting {
		return selected
	}
	if running := m.runningTargetSandbox(); running != nil {
		return running
	}
	for i := range m.sandboxes {
		if m.sandboxes[i].State == tuiStopped {
			return &m.sandboxes[i]
		}
	}
	return nil
}

func (m *sandboxTUIModel) runningTargetSandbox() *tuiSandbox {
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
	count := m.entryCount()
	if m.page == tuiOverviewPage {
		count = len(m.sandboxes)
	}
	m.cursor = clampInt(index, 0, maxInt(0, count-1))
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
	if m.page == tuiOverviewPage {
		visible := m.overviewNavigationCapacity(layout)
		m.cursor = clampInt(m.cursor, 0, maxInt(0, len(m.sandboxes)-1))
		if m.cursor < m.scrollRow {
			m.scrollRow = m.cursor
		}
		if m.cursor >= m.scrollRow+visible {
			m.scrollRow = m.cursor - visible + 1
		}
		m.scrollRow = clampInt(m.scrollRow, 0, maxInt(0, len(m.sandboxes)-visible))
		return
	}
	if m.usesMasterDetail(layout) {
		visible := m.masterVisibleItems(layout)
		if m.cursor < m.scrollRow {
			m.scrollRow = m.cursor
		}
		if m.cursor >= m.scrollRow+visible {
			m.scrollRow = m.cursor - visible + 1
		}
		m.scrollRow = clampInt(m.scrollRow, 0, maxInt(0, m.entryCount()-visible))
		return
	}
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
	m.ensureCursorVisible()
	m.ensureTableCursorVisible()
}

func (m *sandboxTUIModel) cyclePage(delta int) {
	pages := []tuiPage{tuiOverviewPage, tuiSandboxesPage, tuiTrafficPage, tuiRulesPage, tuiPortsPage, tuiPacketsPage, tuiMountsPage, tuiSecretsPage, tuiMCPPage, tuiImagesPage}
	current := 0
	for index, page := range pages {
		if page == m.page {
			current = index
			break
		}
	}
	next := (current + delta%len(pages) + len(pages)) % len(pages)
	m.setPage(pages[next])
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
	case tuiSecretsPage:
		return &m.secretCursor, &m.secretScroll, len(m.secrets)
	case tuiMCPPage:
		return &m.mcpCursor, &m.mcpScroll, len(m.mcpServers)
	case tuiImagesPage:
		if m.imageSection == tuiImageSectionCredentials {
			return &m.registryCursor, &m.registryScroll, len(m.registries)
		}
		return &m.imageCursor, &m.imageScroll, len(m.images)
	case tuiPacketsPage:
		return &m.packetCursor, &m.packetScroll, len(m.packets)
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

func (m sandboxTUIModel) selectedTableKeys() (traffic, rule, mount, port, secret, mcp, image, registry string) {
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
	if m.secretCursor >= 0 && m.secretCursor < len(m.secrets) {
		secret = secretRowKey(m.secrets[m.secretCursor])
	}
	if m.mcpCursor >= 0 && m.mcpCursor < len(m.mcpServers) {
		mcp = mcpRowKey(m.mcpServers[m.mcpCursor])
	}
	if m.imageCursor >= 0 && m.imageCursor < len(m.images) {
		image = imageRowKey(m.images[m.imageCursor])
	}
	if m.registryCursor >= 0 && m.registryCursor < len(m.registries) {
		registry = m.registries[m.registryCursor].Registry
	}
	return
}

func (m *sandboxTUIModel) restoreTableSelections(traffic, rule, mount, port, secret, mcp, image, registry string) {
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
	for i := range m.secrets {
		if secret != "" && secretRowKey(m.secrets[i]) == secret {
			m.secretCursor = i
			break
		}
	}
	for i := range m.mcpServers {
		if mcp != "" && mcpRowKey(m.mcpServers[i]) == mcp {
			m.mcpCursor = i
			break
		}
	}
	for i := range m.images {
		if image != "" && imageRowKey(m.images[i]) == image {
			m.imageCursor = i
			break
		}
	}
	for i := range m.registries {
		if registry != "" && m.registries[i].Registry == registry {
			m.registryCursor = i
			break
		}
	}
	m.trafficCursor = clampTableCursor(m.trafficCursor, len(m.traffic))
	m.rulesCursor = clampTableCursor(m.rulesCursor, len(m.rules))
	m.mountCursor = clampTableCursor(m.mountCursor, len(m.mounts))
	m.portCursor = clampTableCursor(m.portCursor, len(m.ports))
	m.secretCursor = clampTableCursor(m.secretCursor, len(m.secrets))
	m.mcpCursor = clampTableCursor(m.mcpCursor, len(m.mcpServers))
	m.imageCursor = clampTableCursor(m.imageCursor, len(m.images))
	m.registryCursor = clampTableCursor(m.registryCursor, len(m.registries))
}

func trafficRowKey(row tuiTrafficRow) string {
	// DNS traffic is keyed by queried host in the recorder, but every query is
	// sent to the same gateway address and port. Include Host so a refresh does
	// not collapse several DNS rows onto the first (most recently sorted) one.
	return fmt.Sprintf("%s\x00%s\x00%s\x00%s\x00%d\x00%t", row.Sandbox, row.Host, row.Address, row.Protocol, row.Port, row.Allowed)
}

func removableRule(row tuiRuleRow) bool {
	return strings.HasPrefix(row.Source, "rule ") || row.Source == "domain"
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

func secretRowKey(row tuiSecretRow) string { return row.Sandbox + "\x00" + row.Name }

func mcpRowKey(row tuiMCPRow) string { return row.Sandbox + "\x00" + row.Name + "\x00" + row.Type }

// imageRowKey keys on ref+arch (the store's index granularity) rather than
// digest so a re-pull of the same tag keeps the selection.
func imageRowKey(row tuiImageRow) string { return row.Ref + "\x00" + row.Arch }

func clampTableCursor(cursor, count int) int {
	if count == 0 {
		return 0
	}
	return clampInt(cursor, 0, count-1)
}

func refreshSandboxesCmd(service dashboardapi.Service) tea.Cmd {
	return func() tea.Msg {
		data, err := service.Snapshot()
		sanitizeSnapshot(&data)
		return tuiRefreshMsg{
			sandboxes: data.Sandboxes, traffic: data.Traffic,
			rules: data.Rules, mounts: data.Mounts, ports: data.Ports, secrets: data.Secrets,
			mcp: data.MCPServers, images: data.Images, registries: data.Registries,
			err: err, at: time.Now(),
		}
	}
}

func tuiTickCmd() tea.Cmd {
	return tea.Tick(2*time.Second, func(time.Time) tea.Msg { return tuiTickMsg{} })
}

func compactCommandError(output string, err error) string {
	output = strings.TrimSpace(output)
	if output == "" {
		return err.Error()
	}
	lines := strings.Split(output, "\n")
	// Progress output is useful while an operation is running, but it must not
	// displace the diagnostic once the command fails. In particular, a wrapped
	// download progress line can consume the toast's entire two-line body.
	diagnostics := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if _, progress := operationProgressLine(line); !progress {
			diagnostics = append(diagnostics, line)
		}
	}
	if len(diagnostics) > 0 {
		lines = diagnostics
	}
	if errText := strings.TrimSpace(err.Error()); errText != "" &&
		!strings.Contains(strings.Join(lines, "\n"), errText) {
		lines = append(lines, errText)
	}
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
	case "rule add":
		return "Add network rule"
	case "rule remove":
		return "Remove network rule"
	case "secret add":
		return "Add secret"
	case "secret remove":
		return "Delete secret"
	case "mcp configure":
		return "Save MCP server"
	case "mcp filesystem":
		return "Save MCP filesystem server"
	case "mcp remove":
		return "Remove MCP server"
	case "image pull":
		return "Pull image"
	case "image remove":
		return "Remove image"
	case "image prune":
		return "Prune images"
	case "registry login":
		return "Registry login"
	case "registry logout":
		return "Registry logout"
	case "update":
		return "Update Gantry"
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
	case "rule add":
		return "Network rule added"
	case "rule remove":
		return "Network rule removed"
	case "secret add":
		return "Secret added"
	case "secret remove":
		return "Secret deleted"
	case "mcp configure":
		return "MCP server saved"
	case "mcp filesystem":
		return "MCP filesystem server saved"
	case "mcp remove":
		return "MCP server removed"
	case "image pull":
		return "Image pulled"
	case "image remove":
		return "Image removed"
	case "image prune":
		return "Images pruned"
	case "registry login":
		return "Login stored"
	case "registry logout":
		return "Logged out"
	case "update":
		return "Gantry updated"
	default:
		return actionTitle(action) + " complete"
	}
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
