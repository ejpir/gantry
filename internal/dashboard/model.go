package dashboard

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	dashboardapi "github.com/ejpir/gantry/internal/dashboard/api"
	"github.com/ejpir/gantry/internal/sandbox/lifecycle"
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
	defer model.operations.close()
	program := tea.NewProgram(
		&model,
		tea.WithInput(os.Stdin),
		tea.WithOutput(os.Stdout),
	)
	watchCtx, stopWatches := context.WithCancel(context.Background())
	defer stopWatches()
	stopRemotes := startRemoteWatches(watchCtx, program.Send)
	defer stopRemotes()
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
	tuiAuditPage
	tuiRemotesPage
	tuiPageCount
)

type tuiSandbox = dashboardapi.Sandbox
type tuiTrafficRow = dashboardapi.Traffic
type tuiRuleRow = dashboardapi.Rule
type tuiMountRow = dashboardapi.Mount
type tuiPortRow = dashboardapi.Port
type tuiSecretRow = dashboardapi.Secret
type tuiMCPRow = dashboardapi.MCPServer
type tuiAuditRow = dashboardapi.AuditEvent
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
	tuiAuditDetailDialog
	tuiImagePullDialog
	tuiImageRemoveDialog
	tuiImagePruneDialog
	tuiRegistryLoginDialog
	tuiRegistryLogoutDialog
	tuiSandboxFilterDialog
	tuiSortDialog
	tuiCreateLocationDialog
	tuiRemoteProfilesDialog
	tuiOrganizationLoginDialog
	tuiOrganizationRemotesDialog
	tuiRemoteAddDialog
	tuiRemoteRemoveDialog
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
	owner      tuiRefreshOwner
	sandboxes  []tuiSandbox
	traffic    []tuiTrafficRow
	rules      []tuiRuleRow
	mounts     []tuiMountRow
	ports      []tuiPortRow
	secrets    []tuiSecretRow
	mcp        []tuiMCPRow
	audit      []tuiAuditRow
	images     []tuiImageRow
	registries []tuiRegistryRow
	err        error
	at         time.Time
}

type tuiTickMsg struct{}

type tuiPacketPollMsg struct{}

type tuiProcessDoneMsg struct {
	owner  tuiOperationOwner
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
	owner  tuiOperationOwner
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
	operations *dashboardOperations
	service    dashboardapi.Service
	limits     dashboardapi.ResourceLimits

	tuiPageState
	tuiSelectionState
	remotes   map[string]remoteSection
	sandboxes []tuiSandbox

	viewSource         *tuiRefreshMsg
	packetSource       []tuiPacketRow
	sandboxFilter      string
	sandboxFilterInput textinput.Model
	sorts              [tuiPageCount + 1]tuiSortState
	sortCursor         int

	traffic       []tuiTrafficRow
	rules         []tuiRuleRow
	mounts        []tuiMountRow
	ports         []tuiPortRow
	secrets       []tuiSecretRow
	mcpServers    []tuiMCPRow
	auditEvents   []tuiAuditRow
	auditDetail   *tuiAuditRow
	images        []tuiImageRow
	registries    []tuiRegistryRow
	imageSection  string
	packets       []tuiPacketRow
	packetAfter   map[string]uint64
	packetLoading bool
	packetPaused  bool
	packetError   string
	packetEvicted uint64
	packetDetail  *tuiPacketRow

	width  int
	height int
	dark   bool

	loading bool
	tuiRefreshState
	lastUpdate time.Time
	tuiOperationState

	spinner   spinner.Model
	animating bool
	tuiNotificationState

	updateStatus  selfupdate.Status
	updateChecked bool
	exitMessage   string

	tuiDialogState
	createDialogModel
	remoteOnboarding
	editDialogState
	shareDialogState
	portDialogState
	policyDialogState
	ruleDialogState
	secretDialogState
	mcpDialogState
	imageDialogState

	lastClickIndex int
	lastClickKind  string
	lastClickAt    time.Time

	// dashboardHits is emitted by the last render pass. Mouse events consume
	// this map instead of independently reconstructing component positions.
	dashboardHits     []tuiHitTarget
	pendingRemoteOpen *tuiSandbox
	trafficHistory    map[string][]uint64
	trafficTotals     map[string]uint64
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
	createMemory := newMemorySlider(int(limits.MinMemoryMB), int(limits.MaxMemoryMB), 512)
	createDisk := newResourceSlider(int(limits.MinDiskSizeMiB), int(limits.MaxDiskSizeMiB), 512, int(limits.DefaultDiskSizeMiB))
	editCPUs := newResourceSlider(1, limits.MaxVCPUs, 1, 1)
	editMemory := newMemorySlider(int(limits.MinMemoryMB), int(limits.MaxMemoryMB), 512)
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
		sandboxFilterInput: textinput.New(),
		operations:         newDashboardOperations(),
		service:            service,
		tuiPageState:       newTUIPageState(),
		limits:             limits,
		width:              100,
		height:             30,
		dark:               true,
		loading:            true,
		tuiRefreshState:    newTUIRefreshState(),
		spinner:            sp,
		animating:          true,
		createDialogModel: createDialogModel{
			createErrFocus:  -1,
			createName:      name,
			createImage:     image,
			createCPUs:      createCPUs,
			createMemory:    createMemory,
			createDisk:      createDisk,
			createRuntime:   createRuntimeCrun,
			createIsolation: "auto",
		},
		editDialogState: editDialogState{editCPUs: editCPUs, editMemory: editMemory},
		shareDialogState: shareDialogState{
			shareTag: shareTag, sharePath: sharePath, shareMount: shareMount, shareOwner: shareOwner, shareRO: true,
		},
		portDialogState:   portDialogState{portBind: portBind, portGuest: portGuest},
		policyDialogState: policyDialogState{policyPath: policyPath},
		ruleDialogState: ruleDialogState{
			ruleTarget: ruleTarget, rulePorts: rulePorts, ruleAction: ruleActionDeny, ruleProtocol: ruleProtocolTCP,
		},
		secretDialogState: secretDialogState{secretName: secretName, secretValue: secretValue},
		mcpDialogState: mcpDialogState{
			mcpName: mcpName, mcpURL: mcpURL, mcpAuthHeader: mcpAuthHeader, mcpAuthRef: mcpAuthRef,
			mcpAllow: mcpAllow, mcpDeny: mcpDeny, mcpRedact: mcpRedact, mcpFSRoot: mcpFSRoot, mcpFSUser: mcpFSUser,
		},
		imageDialogState: imageDialogState{
			pullRef: pullRef, pullArch: "auto", loginRegistry: loginRegistry,
			loginUsername: loginUsername, loginPassword: loginPassword,
		},
		imageSection:   tuiImageSectionImages,
		lastClickIndex: -1,
		packetAfter:    make(map[string]uint64),
		trafficHistory: make(map[string][]uint64),
		trafficTotals:  make(map[string]uint64),
	}
	m.applyInputTheme()
	return m
}

func (m sandboxTUIModel) Init() tea.Cmd {
	return tea.Batch(
		refreshSandboxesCmd(m.service, m.tuiRefreshState.Current()),
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
		if m.tuiOperationState.Phase() == tuiOperationIdle {
			if owner, ok := m.tuiRefreshState.Begin(false); ok {
				return m, refreshSandboxesCmd(m.service, owner)
			}
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
	case remoteSectionMsg:
		if m.remoteGenerations == nil {
			m.remoteGenerations = make(map[string]uint64)
		}
		name := msg.snapshot.Remote
		if msg.generation < m.remoteGenerations[name] {
			return m, nil
		}
		m.remoteGenerations[name] = msg.generation
		if m.remotes == nil {
			m.remotes = make(map[string]remoteSection)
		}
		if msg.removed {
			delete(m.remotes, name)
		} else {
			m.remotes[name] = remoteSection(msg.snapshot)
		}
		// Local discovery owns viewSource. Once it exists, project every live
		// remote inventory into Overview and Sandboxes without waiting for the
		// next local refresh. Unavailable sources contribute no stale rows.
		if m.viewSource != nil {
			m.rebuildView(false)
			m.sampleSandboxTraffic(m.sandboxes)
		}
		m.ensureTableCursorVisible()
		return m, nil
	case remoteConfigMsg:
		m.remoteConfigError = msg.error
		return m, nil
	case remoteCatalogMsg:
		m.availableRemotes = msg.available
		m.ensureTableCursorVisible()
		return m, nil
	case onboardResultMsg:
		return m, m.handleOnboardResult(msg)
	case onboardURLMsg:
		if msg.generation == m.onboardGeneration {
			m.onboardURL, m.onboardStatus = msg.url, "Waiting for browser sign-in… esc cancels."
			if msg.browserFailed {
				m.onboardStatus = "Browser could not open automatically. Use the URL below; esc cancels."
			}
		}
		return m, nil
	case onboardStreamMsg:
		_, cmd := m.Update(msg.event)
		return m, tea.Batch(cmd, waitOnboardStream(msg.stream))
	case tuiRefreshMsg:
		return m.handleRefresh(msg)
	case tuiTickMsg:
		cmds := []tea.Cmd{tuiTickCmd()}
		if m.tuiOperationState.Phase() == tuiOperationIdle {
			if owner, ok := m.tuiRefreshState.Begin(false); ok {
				cmds = append(cmds, refreshSandboxesCmd(m.service, owner))
			}
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
			done := *msg.event.done
			done.owner = msg.owner
			if done.action == "" {
				done.action, done.name = msg.owner.Action(), msg.owner.Name()
			}
			return m.handleProcessDone(done)
		}
		_ = m.tuiOperationState.SetProgress(msg.owner, safeUILine(msg.event.progress))
		return m, waitTUIProcessStream(msg.stream, msg.owner)
	case tuiToastExpiredMsg:
		m.tuiNotificationState.expire(msg.gen)
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
	if !m.tuiRefreshState.Finish(msg.owner) {
		return m, nil
	}
	wasLoading := m.loading
	m.loading = false
	m.lastUpdate = msg.at
	m.lastClickAt = time.Time{}
	m.lastClickKind = ""
	if msg.err != nil {
		return m, m.showToast(tuiToastError, "Refresh failed", msg.err.Error())
	}

	selectedKey := ""
	selectedNewCard := !wasLoading && m.onNewCard()
	if selected := m.selected(); selected != nil {
		selectedKey = sandboxRowKey(*selected)
	}
	trafficKey, ruleKey, mountKey, portKey, secretKey, mcpKey, imageKey, registryKey := m.selectedTableKeys()
	packetKey := m.selectedPacketKey()
	auditKey := m.selectedAuditKey()
	m.rememberViewSource()
	m.viewSource = &msg
	m.rebuildRows()
	m.sampleSandboxTraffic(m.sandboxes)
	m.restorePacketSelection(packetKey)
	m.restoreAuditSelection(auditKey)
	m.dashboardHits = nil

	target := m.tuiOperationState.Selection()
	found := false
	for i := range m.sandboxes {
		row := m.sandboxes[i]
		matches := target == "" && sandboxRowKey(row) == selectedKey
		// Operation selections are local sandbox names. Requiring an empty
		// source prevents a same-named remote row from stealing selection.
		if target != "" {
			matches = row.Remote == "" && row.Name == target
		}
		if matches {
			m.tuiSelectionState.setCardCursor(i, m.entryCount())
			found = true
			break
		}
	}
	// A refresh that was already in flight can race a create process. Keep the
	// requested selection until the sandbox appears; handleProcessDone clears
	// it explicitly if creation fails.
	if found {
		m.tuiOperationState.ClearSelection()
	}
	if !found && selectedNewCard {
		m.tuiSelectionState.setCardCursor(len(m.sandboxes), m.entryCount())
	} else if !found && m.cursor > len(m.sandboxes) {
		m.tuiSelectionState.setCardCursor(len(m.sandboxes), m.entryCount())
	}
	m.restoreTableSelections(trafficKey, ruleKey, mountKey, portKey, secretKey, mcpKey, imageKey, registryKey)
	m.ensureCursorVisible()
	m.ensureTableCursorVisible()
	return m, m.ensureAnimation()
}

func (m *sandboxTUIModel) handleProcessDone(msg tuiProcessDoneMsg) (tea.Model, tea.Cmd) {
	if !m.tuiOperationState.Finish(msg.owner) {
		return m, nil
	}
	if msg.action == "enable remote SSH" {
		target := m.pendingRemoteOpen
		m.pendingRemoteOpen = nil
		if msg.err == nil && target != nil {
			refreshOwner := m.tuiRefreshState.Restart(false)
			_, open := m.beginRemoteAction("open", *target, []string{"ssh", target.Name, "-remote", target.Remote}, true)
			return m, tea.Batch(refreshSandboxesCmd(m.service, refreshOwner), open)
		}
	}
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
	refreshOwner := m.tuiRefreshState.Restart(false)

	kind, title, body := tuiToastSuccess, actionPastTense(msg.action), msg.name
	if msg.err != nil {
		kind = tuiToastError
		title = actionTitle(msg.action) + " failed"
		body = compactCommandError(msg.output, msg.err)
		m.tuiOperationState.ClearSelection()
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
	return m, tea.Batch(refreshSandboxesCmd(m.service, refreshOwner), m.showToast(kind, title, body))
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
	if m.tuiOperationState.Phase() == tuiOperationRunning {
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
	case tuiRemotesPage:
		return m.updateRemoteActionKey(key)

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
				m.tuiDialogState.openConfirmation(tuiShareRemoveDialog)
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
				m.tuiDialogState.openConfirmation(tuiRuleRemoveDialog)
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
				m.tuiDialogState.openConfirmation(tuiPortUnpublishDialog)
			}
			return nil, true
		}
	case tuiSecretsPage:
		switch key {
		case "a":
			return m.openSecretAddDialog(), true
		case "d", "delete", "x":
			if m.selectedSecret() != nil {
				m.tuiDialogState.openConfirmation(tuiSecretRemoveDialog)
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
			m.tuiDialogState.openConfirmation(tuiMCPRemoveDialog)
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
				m.tuiDialogState.openConfirmation(tuiRegistryLogoutDialog)
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
			m.tuiDialogState.openConfirmation(tuiImageRemoveDialog)
			return nil, true
		case "u":
			if m.prunableImageCount() == 0 {
				return m.showToast(tuiToastInfo, "Nothing to prune", "Every cached image is referenced by a sandbox."), true
			}
			m.tuiDialogState.openConfirmation(tuiImagePruneDialog)
			return nil, true
		}
		return nil, false
	case tuiAuditPage:
		if key == "enter" || key == "d" || key == "i" {
			m.openAuditDetail()
			return nil, true
		}
	case tuiPacketsPage:
		return m.updatePacketActionKey(key)
	}
	return nil, false
}

func (m *sandboxTUIModel) updateGlobalKey(key string) (tea.Cmd, bool) {
	switch key {
	case "/":
		return m.openFilterDialog(), true
	case "S":
		m.openSortDialog()
		return nil, true
	case "q", "ctrl+c":
		return tea.Quit, true
	case "n":
		return m.openCreateWizard(), true
	case "r":
		return m.refreshCmd(), true
	case "U":
		if m.updateStatus.Available {
			m.tuiDialogState.openConfirmation(tuiUpdateDialog)
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
		m.tuiDialogState.open(tuiHelpDialog)
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
	case "A":
		m.setPage(tuiAuditPage)
	case "B":
		m.setPage(tuiRemotesPage)
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
	owner, ok := m.tuiRefreshState.Begin(true)
	if !ok {
		return nil
	}
	return tea.Batch(refreshSandboxesCmd(m.service, owner), m.ensureAnimation())
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
	slot, count, ok := m.tableSelection()
	if !ok || !m.tuiSelectionState.tableBoundary(slot, end, count) {
		return
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
			return m.openCreateWizard()
		}
		m.setPage(tuiSandboxesPage)
	case "t":
		selected := m.selected()
		m.setPage(tuiTrafficPage)
		if selected != nil {
			for index, row := range m.traffic {
				if row.Sandbox == selected.Name && row.Remote == selected.Remote {
					m.tuiSelectionState.setTableCursor(tuiTrafficSelection, index, len(m.traffic))
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
			m.tuiDialogState.open(tuiInfoDialog)
		}
	case "d", "delete", "x":
		if m.selected() != nil {
			m.tuiDialogState.openConfirmation(tuiRemoveDialog)
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
			m.tuiDialogState.open(tuiInfoDialog)
		}
	case "e":
		return m.openEditDialog()
	case "d", "delete", "x":
		if m.selected() != nil {
			m.tuiDialogState.openConfirmation(tuiRemoveDialog)
		}
	}
	return nil
}

func (m *sandboxTUIModel) primaryAction() (tea.Model, tea.Cmd) {
	if m.onNewCard() {
		return m, m.openCreateWizard()
	}
	selected := m.selected()
	if selected == nil {
		return m, nil
	}
	if selected.Remote != "" {
		if selected.State == tuiRunning {
			if !selected.SSH {
				copy := *selected
				m.pendingRemoteOpen = &copy
				return m.beginServiceAction("enable remote SSH", sandboxOperationName(*selected),
					enableRemoteSSHCmd(m.serviceForRemote(selected.Remote), *selected))
			}
			return m.beginRemoteAction("open", *selected, []string{"ssh", selected.Name, "-remote", selected.Remote}, true)
		}
		if selected.State == tuiStarting {
			return m, m.showToast(tuiToastInfo, "Sandbox is starting", sandboxOperationName(*selected))
		}
		return m.beginRemoteAction("start", *selected, []string{"resume", selected.Name, "-remote", selected.Remote}, false)
	}
	if selected.State == tuiRunning {
		return m.beginAction("open", selected.Name, []string{"exec", selected.Name}, true)
	}
	if selected.State == tuiStarting {
		return m, m.showToast(tuiToastInfo, "Sandbox is starting", selected.Name)
	}
	return m.beginStart("start", lifecycle.StartRequest{Name: selected.Name, Mode: lifecycle.Resume})
}

func (m *sandboxTUIModel) toggleSelected() (tea.Model, tea.Cmd) {
	selected := m.selected()
	if selected == nil {
		return m, nil
	}
	if selected.Remote != "" {
		switch selected.State {
		case tuiRunning:
			return m.beginRemoteAction("stop", *selected, []string{"stop", selected.Name, "-remote", selected.Remote}, false)
		case tuiStarting:
			return m, m.showToast(tuiToastInfo, "Sandbox is starting", sandboxOperationName(*selected))
		default:
			return m.beginRemoteAction("start", *selected, []string{"resume", selected.Name, "-remote", selected.Remote}, false)
		}
	}
	switch selected.State {
	case tuiRunning:
		return m.beginAction("stop", selected.Name, []string{"stop", selected.Name}, false)
	case tuiStarting:
		return m, m.showToast(tuiToastInfo, "Sandbox is starting", selected.Name)
	default:
		return m.beginStart("start", lifecycle.StartRequest{Name: selected.Name, Mode: lifecycle.Resume})
	}
}

func (m *sandboxTUIModel) beginAction(action, name string, argv []string, interactive bool) (tea.Model, tea.Cmd) {
	return m.beginCommandAction(action, name, m.service, argv, interactive)
}

func (m *sandboxTUIModel) beginCommandAction(action, name string, service dashboardapi.Service, argv []string, interactive bool) (tea.Model, tea.Cmd) {
	owner, ok := m.tuiOperationState.Begin(action, name, action == "create" || action == "start")
	if !ok {
		return m, nil
	}
	m.tuiDialogState.dismiss()
	return m, tea.Batch(runTUIProcessCmd(m.operations, service, owner, argv, interactive), m.ensureAnimation())
}

// beginRemoteAction always carries an explicit profile selector and never
// creates a local selection handoff. This keeps same-named local and remote
// sandboxes isolated even when GANTRY_REMOTE is set in the environment.
func (m *sandboxTUIModel) beginRemoteAction(action string, sandbox tuiSandbox, argv []string, interactive bool) (tea.Model, tea.Cmd) {
	owner, ok := m.tuiOperationState.Begin(action, sandboxOperationName(sandbox), false)
	if !ok {
		return m, nil
	}
	m.tuiDialogState.dismiss()
	return m, tea.Batch(runTUIProcessCmd(m.operations, m.service, owner, argv, interactive), m.ensureAnimation())
}

// beginServiceAction is the single admission point for in-process dashboard
// mutations. Validation remains with each form, while this owner prevents a
// second command from replacing the result routing of the active operation.
func (m *sandboxTUIModel) beginServiceAction(action, name string, command tea.Cmd) (tea.Model, tea.Cmd) {
	owner, ok := m.tuiOperationState.Begin(action, name, false)
	if !ok {
		return m, nil
	}
	m.closeDialog()
	return m, tea.Batch(ownTUIOperationCmd(owner, command), m.ensureAnimation())
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

func enableRemoteSSHCmd(service dashboardapi.Service, sandbox tuiSandbox) tea.Cmd {
	return func() tea.Msg {
		request := dashboardapi.SandboxConfigRequest{
			Name: sandbox.Name, MemMB: sandbox.MemMB, VCPUs: sandbox.VCPUs,
			ProcessIsolation: sandbox.ProcessIsolation, SSH: true, DevContainers: sandbox.DevContainers,
		}
		_, err := service.ConfigureSandbox(request)
		return tuiProcessDoneMsg{action: "enable remote SSH", name: sandboxOperationName(sandbox), err: err}
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

func publishPortCmd(service dashboardapi.Service, name, spec string) tea.Cmd {
	return func() tea.Msg {
		err := service.PublishPort(name, spec)
		return tuiProcessDoneMsg{action: "port publish", name: name + "/" + spec, err: err}
	}
}

func unpublishPortCmd(service dashboardapi.Service, name, spec string) tea.Cmd {
	return func() tea.Msg {
		err := service.UnpublishPort(name, spec)
		return tuiProcessDoneMsg{action: "port unpublish", name: name + "/" + spec, err: err}
	}
}

func (m *sandboxTUIModel) needsAnimation() bool {
	if m.loading || m.tuiRefreshState.Visible() || m.tuiOperationState.Phase() == tuiOperationRunning {
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
	generation := m.tuiNotificationState.publish(kind, safeUILine(title), strings.TrimSpace(safeUIBlock(body)))
	return tea.Tick(4*time.Second, func(time.Time) tea.Msg { return tuiToastExpiredMsg{gen: generation} })
}

func sandboxDisplayName(sandbox tuiSandbox) string {
	if sandbox.Remote == "" {
		return sandbox.Name
	}
	return sandbox.Name + "  [remote:" + sandbox.Remote + "]"
}

func sandboxOperationName(sandbox tuiSandbox) string {
	return remoteOperationLabel(sandbox.Name, sandbox.Remote)
}

func sourceDisplayName(name, remote string) string {
	if remote == "" {
		return name
	}
	return name + " [remote:" + remote + "]"
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
	remote := ""
	if row := m.selectedImage(); row != nil {
		remote = row.Remote
	}
	count := 0
	for _, row := range m.images {
		if row.Remote == remote && !row.InUse {
			count++
		}
	}
	return count
}

func (m *sandboxTUIModel) sandboxAtSource(name, remote string) *tuiSandbox {
	for i := range m.sandboxes {
		if m.sandboxes[i].Remote == remote && m.sandboxes[i].Name == name {
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
	m.tuiSelectionState.setCardCursor(index, count)
	m.ensureCursorVisible()
}

func (m *sandboxTUIModel) moveCursor(dx, dy int) {
	layout := m.dashboardLayout()
	candidate := m.cursor
	if dx != 0 {
		row := m.cursor / layout.cols
		horizontal := m.cursor + dx
		if horizontal >= 0 && horizontal < m.entryCount() && horizontal/layout.cols == row {
			candidate = horizontal
		}
	}
	if dy != 0 {
		candidate = m.cursor + dy*layout.cols
		if candidate < 0 {
			candidate = 0
		}
		if candidate >= m.entryCount() {
			lastRowStart := ((m.entryCount() - 1) / layout.cols) * layout.cols
			candidate = minInt(m.entryCount()-1, lastRowStart+(m.cursor%layout.cols))
		}
	}
	m.tuiSelectionState.setCardCursor(candidate, m.entryCount())
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
		m.tuiSelectionState.ensureCardListVisible(len(m.sandboxes), m.overviewNavigationCapacity(layout))
		return
	}
	if m.usesMasterDetail(layout) {
		m.tuiSelectionState.ensureCardListVisible(m.entryCount(), m.masterVisibleItems(layout))
		return
	}
	m.tuiSelectionState.ensureCardGridVisible(m.entryCount(), layout.cols, layout.visibleRows, layout.maxScrollRow(m.entryCount()))
}

func (m *sandboxTUIModel) setPage(page tuiPage) {
	if !m.tuiPageState.transition(page) {
		return
	}
	if m.viewSource != nil {
		m.rebuildView(false)
	}
	m.ensureCursorVisible()
	m.ensureTableCursorVisible()
}

func (m *sandboxTUIModel) cyclePage(delta int) {
	m.setPage(m.tuiPageState.cycle(delta))
}

func (m *sandboxTUIModel) tableSelection() (slot tuiSelectionSlot, count int, ok bool) {
	switch m.page {
	case tuiTrafficPage:
		return tuiTrafficSelection, len(m.traffic), true
	case tuiRulesPage:
		return tuiRulesSelection, len(m.rules), true
	case tuiMountsPage:
		return tuiMountsSelection, len(m.mounts), true
	case tuiPortsPage:
		return tuiPortsSelection, len(m.ports), true
	case tuiSecretsPage:
		return tuiSecretsSelection, len(m.secrets), true
	case tuiMCPPage:
		return tuiMCPSelection, len(m.mcpServers), true
	case tuiAuditPage:
		return tuiAuditSelection, len(m.auditEvents), true
	case tuiRemotesPage:
		return tuiRemoteSelection, len(m.remoteLines()), true
	case tuiImagesPage:
		if m.imageSection == tuiImageSectionCredentials {
			return tuiRegistrySelection, len(m.registries), true
		}
		return tuiImageSelection, len(m.images), true
	case tuiPacketsPage:
		return tuiPacketSelection, len(m.packets), true
	default:
		return 0, 0, false
	}
}

func (m *sandboxTUIModel) tableState() (cursor, scroll, count int, ok bool) {
	slot, count, ok := m.tableSelection()
	if !ok {
		return 0, 0, 0, false
	}
	cursor, scroll, ok = m.tuiSelectionState.tablePosition(slot)
	return cursor, scroll, count, ok
}

func (m *sandboxTUIModel) moveTableCursor(delta int) {
	slot, count, ok := m.tableSelection()
	if !ok || !m.tuiSelectionState.moveTable(slot, delta, count) {
		return
	}
	m.ensureTableCursorVisible()
}

func (m *sandboxTUIModel) ensureTableCursorVisible() {
	slot, count, ok := m.tableSelection()
	if !ok {
		return
	}
	m.tuiSelectionState.ensureTableVisible(slot, count, m.tableVisibleRows())
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
		registry = registryRowKey(m.registries[m.registryCursor])
	}
	return
}

func (m *sandboxTUIModel) restoreTableSelections(traffic, rule, mount, port, secret, mcp, image, registry string) {
	for i := range m.traffic {
		if traffic != "" && trafficRowKey(m.traffic[i]) == traffic {
			m.tuiSelectionState.setTableCursor(tuiTrafficSelection, i, len(m.traffic))
			break
		}
	}
	for i := range m.rules {
		if rule != "" && ruleRowKey(m.rules[i]) == rule {
			m.tuiSelectionState.setTableCursor(tuiRulesSelection, i, len(m.rules))
			break
		}
	}
	for i := range m.mounts {
		if mount != "" && mountRowKey(m.mounts[i]) == mount {
			m.tuiSelectionState.setTableCursor(tuiMountsSelection, i, len(m.mounts))
			break
		}
	}
	for i := range m.ports {
		if port != "" && portRowKey(m.ports[i]) == port {
			m.tuiSelectionState.setTableCursor(tuiPortsSelection, i, len(m.ports))
			break
		}
	}
	for i := range m.secrets {
		if secret != "" && secretRowKey(m.secrets[i]) == secret {
			m.tuiSelectionState.setTableCursor(tuiSecretsSelection, i, len(m.secrets))
			break
		}
	}
	for i := range m.mcpServers {
		if mcp != "" && mcpRowKey(m.mcpServers[i]) == mcp {
			m.tuiSelectionState.setTableCursor(tuiMCPSelection, i, len(m.mcpServers))
			break
		}
	}
	for i := range m.images {
		if image != "" && imageRowKey(m.images[i]) == image {
			m.tuiSelectionState.setTableCursor(tuiImageSelection, i, len(m.images))
			break
		}
	}
	for i := range m.registries {
		if registry != "" && registryRowKey(m.registries[i]) == registry {
			m.tuiSelectionState.setTableCursor(tuiRegistrySelection, i, len(m.registries))
			break
		}
	}
	m.tuiSelectionState.setTableCursor(tuiTrafficSelection, m.trafficCursor, len(m.traffic))
	m.tuiSelectionState.setTableCursor(tuiRulesSelection, m.rulesCursor, len(m.rules))
	m.tuiSelectionState.setTableCursor(tuiMountsSelection, m.mountCursor, len(m.mounts))
	m.tuiSelectionState.setTableCursor(tuiPortsSelection, m.portCursor, len(m.ports))
	m.tuiSelectionState.setTableCursor(tuiSecretsSelection, m.secretCursor, len(m.secrets))
	m.tuiSelectionState.setTableCursor(tuiMCPSelection, m.mcpCursor, len(m.mcpServers))
	m.tuiSelectionState.setTableCursor(tuiImageSelection, m.imageCursor, len(m.images))
	m.tuiSelectionState.setTableCursor(tuiRegistrySelection, m.registryCursor, len(m.registries))
}

func trafficRowKey(row tuiTrafficRow) string {
	// DNS traffic is keyed by queried host in the recorder, but every query is
	// sent to the same gateway address and port. Include Host so a refresh does
	// not collapse several DNS rows onto the first (most recently sorted) one.
	return fmt.Sprintf("%s\x00%s\x00%s\x00%s\x00%s\x00%d\x00%t", row.Remote, row.Sandbox, row.Host, row.Address, row.Protocol, row.Port, row.Allowed)
}

func removableRule(row tuiRuleRow) bool {
	return strings.HasPrefix(row.Source, "rule ") || row.Source == "domain"
}

func ruleRowKey(row tuiRuleRow) string {
	return strings.Join([]string{row.Remote, row.Sandbox, row.Action, row.Target, row.Proto, row.Ports, row.Source}, "\x00")
}

func mountRowKey(row tuiMountRow) string {
	return strings.Join([]string{row.Remote, row.Sandbox, row.Tag, row.Host, row.Guest}, "\x00")
}

func portRowKey(row tuiPortRow) string {
	return strings.Join([]string{row.Remote, row.Sandbox, row.Bind, row.Proto}, "\x00")
}

func secretRowKey(row tuiSecretRow) string {
	return row.Remote + "\x00" + row.Sandbox + "\x00" + row.Name
}

func mcpRowKey(row tuiMCPRow) string {
	return row.Remote + "\x00" + row.Sandbox + "\x00" + row.Name + "\x00" + row.Type
}

// imageRowKey keys on ref+arch (the store's index granularity) rather than
// digest so a re-pull of the same tag keeps the selection.
func imageRowKey(row tuiImageRow) string       { return row.Remote + "\x00" + row.Ref + "\x00" + row.Arch }
func registryRowKey(row tuiRegistryRow) string { return row.Remote + "\x00" + row.Registry }

func refreshSandboxesCmd(service dashboardapi.Service, owner tuiRefreshOwner) tea.Cmd {
	return func() tea.Msg {
		data, err := service.Snapshot()
		sanitizeSnapshot(&data)
		return tuiRefreshMsg{
			owner: owner, sandboxes: data.Sandboxes, traffic: data.Traffic,
			rules: data.Rules, mounts: data.Mounts, ports: data.Ports, secrets: data.Secrets,
			mcp: data.MCPServers, audit: data.Audit, images: data.Images, registries: data.Registries,
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
