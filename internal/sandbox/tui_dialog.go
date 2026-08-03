package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

func (m *sandboxTUIModel) updateDialogKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	if msg.String() == "ctrl+c" {
		return m, func() tea.Msg { return tea.Quit() }
	}
	switch m.dialog {
	case tuiCreateDialog:
		return m.updateCreateDialogKey(msg)
	case tuiShareAddDialog:
		return m.updateShareDialogKey(msg)
	case tuiPortPublishDialog:
		return m.updatePortDialogKey(msg)
	case tuiPortUnpublishDialog:
		switch msg.String() {
		case "esc", "q", "n", "N":
			m.closeDialog()
		case "left", "h":
			m.confirmRemove = false
		case "right", "l", "tab", "shift+tab":
			m.confirmRemove = !m.confirmRemove
		case "y", "Y":
			m.confirmRemove = true
			return m.unpublishSelectedPort()
		case "enter":
			if m.confirmRemove {
				return m.unpublishSelectedPort()
			}
			m.closeDialog()
		}
	case tuiShareRemoveDialog:
		switch msg.String() {
		case "esc", "q", "n", "N":
			m.closeDialog()
		case "left", "h":
			m.confirmRemove = false
		case "right", "l", "tab", "shift+tab":
			m.confirmRemove = !m.confirmRemove
		case "y", "Y":
			m.confirmRemove = true
			return m.removeSelectedShare()
		case "enter":
			if m.confirmRemove {
				return m.removeSelectedShare()
			}
			m.closeDialog()
		}
	case tuiRemoveDialog:
		switch msg.String() {
		case "esc", "q", "n", "N":
			m.closeDialog()
		case "left", "h":
			m.confirmRemove = false
		case "right", "l", "tab", "shift+tab":
			m.confirmRemove = !m.confirmRemove
		case "y", "Y":
			m.confirmRemove = true
			return m.removeSelected()
		case "enter":
			if m.confirmRemove {
				return m.removeSelected()
			}
			m.closeDialog()
		}
	case tuiHelpDialog, tuiInfoDialog:
		switch msg.String() {
		case "esc", "q", "?", "enter", "i":
			m.closeDialog()
		}
	}
	return m, nil
}

func (m *sandboxTUIModel) updateCreateDialogKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.closeDialog()
		return m, nil
	case "tab", "down":
		return m, m.focusCreate((m.createFocus + 1) % 5)
	case "shift+tab", "up":
		return m, m.focusCreate((m.createFocus + 4) % 5)
	case "left", "right", " ", "space":
		switch m.createFocus {
		case 2:
			if m.createRuntime == "runsc" {
				m.createRuntime = "crun"
			} else {
				m.createRuntime = "runsc"
			}
		case 3:
			m.cycleCreateKernel(1)
		}
		return m, nil
	case "ctrl+enter":
		return m.submitCreate()
	case "enter":
		if m.createFocus < 4 {
			return m, m.focusCreate(m.createFocus + 1)
		}
		return m.submitCreate()
	}

	var cmd tea.Cmd
	switch m.createFocus {
	case 0:
		m.createName, cmd = m.createName.Update(msg)
	case 1:
		m.createImage, cmd = m.createImage.Update(msg)
	}
	m.formError = ""
	return m, cmd
}

// createKernelChoices lists the staged guest kernels for this host's arch,
// from the artifacts dir first and the cwd second (AssetPath's two search
// roots). Entry 0 in the dialog is always "auto": the CLI default, which
// downloads the release kernel when nothing is staged.
func createKernelChoices() []string {
	arch := "arm64"
	if runtime.GOARCH == "amd64" {
		arch = "x86_64"
	}
	dirs := []string{"."}
	if d := os.Getenv("GANTRY_ARTIFACTS"); d != "" {
		dirs = append([]string{d}, dirs...)
	} else {
		dirs = append([]string{"artifacts"}, dirs...)
	}
	seen := map[string]bool{}
	var out []string
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || seen[name] {
				continue
			}
			if strings.HasPrefix(name, "gantry-kernel-"+arch) || strings.HasPrefix(name, "nerdbox-kernel-"+arch) {
				seen[name] = true
				out = append(out, filepath.Join(dir, name))
			}
		}
	}
	return out
}

func (m *sandboxTUIModel) cycleCreateKernel(delta int) {
	count := len(m.createKernels) + 1 // +1 for "auto"
	m.createKernel = ((m.createKernel+delta)%count + count) % count
}

// createKernelSelection returns the explicit kernel path, or "" for auto.
func (m *sandboxTUIModel) createKernelSelection() string {
	if m.createKernel <= 0 || m.createKernel > len(m.createKernels) {
		return ""
	}
	return m.createKernels[m.createKernel-1]
}

func (m *sandboxTUIModel) createKernelLabel() string {
	if k := m.createKernelSelection(); k != "" {
		return filepath.Base(k)
	}
	if m.createRuntime == "runsc" {
		return "auto (downloads the 4K-page kernel)"
	}
	return "auto (downloads if needed)"
}

// createArgv builds the CLI argv for the dialog's current choices. Kept
// separate from submitCreate so tests can inspect it without spawning.
func (m *sandboxTUIModel) createArgv(name string) []string {
	argv := []string{"start", name}
	if image := strings.TrimSpace(m.createImage.Value()); image != "" {
		argv = append(argv, "-image", image)
	}
	if m.createRuntime == "runsc" {
		argv = append(argv, "-runtime", "runsc")
	}
	if k := m.createKernelSelection(); k != "" {
		argv = append(argv, "-kernel", k)
	}
	return argv
}

func (m *sandboxTUIModel) openCreateDialog() tea.Cmd {
	m.dialog = tuiCreateDialog
	m.formError = ""
	m.createName.Reset()
	m.createImage.Reset()
	m.createRuntime = "crun"
	m.createKernels = createKernelChoices()
	m.createKernel = 0
	m.resizeInputs()
	return m.focusCreate(0)
}

func (m *sandboxTUIModel) focusCreate(index int) tea.Cmd {
	m.createFocus = clampInt(index, 0, 4)
	m.createName.Blur()
	m.createImage.Blur()
	switch m.createFocus {
	case 0:
		return m.createName.Focus()
	case 1:
		return m.createImage.Focus()
	default:
		return nil
	}
}

func (m *sandboxTUIModel) submitCreate() (tea.Model, tea.Cmd) {
	name := strings.TrimSpace(m.createName.Value())
	if err := ValidateSandboxName(name); err != nil {
		m.formError = err.Error()
		return m, m.focusCreate(0)
	}
	if _, err := os.Stat(sandboxDir(name)); err == nil {
		m.formError = fmt.Sprintf("sandbox %q already exists", name)
		return m, m.focusCreate(0)
	}
	return m.beginAction("create", name, m.createArgv(name), false)
}

func (m *sandboxTUIModel) updateShareDialogKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.closeDialog()
		return m, nil
	case "tab", "down":
		return m, m.focusShare((m.shareFocus + 1) % 4)
	case "shift+tab", "up":
		return m, m.focusShare((m.shareFocus + 3) % 4)
	case "left", "right", " ", "space":
		if m.shareFocus == 2 {
			m.shareRO = !m.shareRO
			return m, nil
		}
	case "ctrl+enter":
		return m.submitShare()
	case "enter":
		if m.shareFocus < 3 {
			return m, m.focusShare(m.shareFocus + 1)
		}
		return m.submitShare()
	}

	var cmd tea.Cmd
	switch m.shareFocus {
	case 0:
		m.shareTag, cmd = m.shareTag.Update(msg)
	case 1:
		m.sharePath, cmd = m.sharePath.Update(msg)
	}
	m.formError = ""
	return m, cmd
}

func (m *sandboxTUIModel) openShareAddDialog(replace bool) tea.Cmd {
	target := m.shareTargetSandbox()
	if target == nil {
		return m.showToast(tuiToastInfo, "No running sandbox", "Start a sandbox before adding a live share.")
	}
	m.dialog = tuiShareAddDialog
	m.formError = ""
	m.shareReplace = replace
	m.shareRO = true
	m.shareTag.Reset()
	m.sharePath.Reset()
	if replace {
		if row := m.selectedMount(); row != nil && row.Error == "" {
			m.shareTag.SetValue(row.Tag)
			m.sharePath.SetValue(row.Host)
			m.shareRO = row.ReadOnly
		}
	}
	m.resizeInputs()
	return m.focusShare(0)
}

func (m *sandboxTUIModel) focusShare(index int) tea.Cmd {
	m.shareFocus = clampInt(index, 0, 3)
	m.shareTag.Blur()
	m.sharePath.Blur()
	switch m.shareFocus {
	case 0:
		return m.shareTag.Focus()
	case 1:
		return m.sharePath.Focus()
	default:
		return nil
	}
}

func (m *sandboxTUIModel) updatePortDialogKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.closeDialog()
		return m, nil
	case "tab", "down":
		return m, m.focusPort((m.portFocus + 1) % 4)
	case "shift+tab", "up":
		return m, m.focusPort((m.portFocus + 3) % 4)
	case "left", "right", " ", "space":
		if m.portFocus == 2 {
			m.portUDP = !m.portUDP
			return m, nil
		}
	case "ctrl+enter":
		return m.submitPort()
	case "enter":
		if m.portFocus < 3 {
			return m, m.focusPort(m.portFocus + 1)
		}
		return m.submitPort()
	}

	var cmd tea.Cmd
	switch m.portFocus {
	case 0:
		m.portBind, cmd = m.portBind.Update(msg)
	case 1:
		m.portGuest, cmd = m.portGuest.Update(msg)
	}
	m.formError = ""
	return m, cmd
}

func (m *sandboxTUIModel) openPortPublishDialog() tea.Cmd {
	target := m.shareTargetSandbox() // same selection rule as live shares
	if target == nil {
		return m.showToast(tuiToastInfo, "No running sandbox", "Start a sandbox before publishing a port.")
	}
	m.dialog = tuiPortPublishDialog
	m.formError = ""
	m.portUDP = false
	m.portBind.Reset()
	m.portGuest.Reset()
	m.resizeInputs()
	return m.focusPort(0)
}

func (m *sandboxTUIModel) focusPort(index int) tea.Cmd {
	m.portFocus = clampInt(index, 0, 3)
	m.portBind.Blur()
	m.portGuest.Blur()
	switch m.portFocus {
	case 0:
		return m.portBind.Focus()
	case 1:
		return m.portGuest.Focus()
	default:
		return nil
	}
}

// portSpecFromDialog composes [IP:]HOST:GUEST[/udp] from the dialog fields.
// Split out for tests: blank bind = auto host port on loopback, a bare
// number = loopback + that port, ip:port widens the bind explicitly.
func (m *sandboxTUIModel) portSpecFromDialog() (string, error) {
	guest := strings.TrimSpace(m.portGuest.Value())
	if guest == "" {
		return "", fmt.Errorf("guest port is required")
	}
	bind := strings.TrimSpace(m.portBind.Value())
	spec := ""
	switch {
	case bind == "":
		spec = guest // auto host port
	case strings.Contains(bind, ":"):
		spec = bind + ":" + guest
	default:
		spec = bind + ":" + guest
	}
	if m.portUDP {
		spec += "/udp"
	}
	if _, err := ParsePortSpec(spec); err != nil {
		return "", err
	}
	return spec, nil
}

func (m *sandboxTUIModel) submitPort() (tea.Model, tea.Cmd) {
	target := m.shareTargetSandbox()
	if target == nil {
		m.formError = "no running sandbox available"
		return m, nil
	}
	spec, err := m.portSpecFromDialog()
	if err != nil {
		m.formError = err.Error()
		if strings.TrimSpace(m.portGuest.Value()) == "" {
			return m, m.focusPort(1)
		}
		return m, m.focusPort(0)
	}
	return m.beginAction("port publish", target.Name+"/"+spec, []string{"ports", "publish", target.Name, spec}, false)
}

func (m *sandboxTUIModel) unpublishSelectedPort() (tea.Model, tea.Cmd) {
	row := m.selectedPort()
	if row == nil || row.Error != "" {
		m.closeDialog()
		return m, nil
	}
	spec := row.Bind + ":" + fmt.Sprintf("%d", row.Guest)
	if row.Proto != "tcp" {
		spec += "/" + row.Proto
	}
	return m.beginAction("port unpublish", row.Sandbox+"/"+row.Bind, []string{"ports", "unpublish", row.Sandbox, spec}, false)
}

func (m *sandboxTUIModel) submitShare() (tea.Model, tea.Cmd) {
	targetName := ""
	if m.shareReplace {
		if row := m.selectedMount(); row != nil {
			targetName = row.Sandbox
		}
	}
	if targetName == "" {
		if target := m.shareTargetSandbox(); target != nil {
			targetName = target.Name
		}
	}
	if targetName == "" {
		m.formError = "no running sandbox available"
		return m, nil
	}
	tag := strings.TrimSpace(m.shareTag.Value())
	path := strings.TrimSpace(m.sharePath.Value())
	if tag == "" {
		m.formError = "tag is required"
		return m, m.focusShare(0)
	}
	if path == "" {
		m.formError = "host path is required"
		return m, m.focusShare(1)
	}
	spec := tag + "=" + path
	if m.shareRO {
		spec += ",ro"
	}
	argv := []string{"share", "add"}
	if m.shareReplace {
		argv = append(argv, "--replace")
	}
	argv = append(argv, targetName, spec)
	action := "share add"
	if m.shareReplace {
		action = "share replace"
	}
	return m.beginAction(action, targetName+"/"+tag, argv, false)
}

func (m *sandboxTUIModel) removeSelectedShare() (tea.Model, tea.Cmd) {
	row := m.selectedMount()
	if row == nil || row.Error != "" {
		m.closeDialog()
		return m, nil
	}
	return m.beginAction("share remove", row.Sandbox+"/"+row.Tag, []string{"share", "remove", row.Sandbox, row.Tag}, false)
}

func (m *sandboxTUIModel) removeSelected() (tea.Model, tea.Cmd) {
	selected := m.selected()
	if selected == nil {
		m.closeDialog()
		return m, nil
	}
	return m.beginAction("delete", selected.Name, []string{"delete", selected.Name}, false)
}

func (m *sandboxTUIModel) closeDialog() {
	m.dialog = tuiNoDialog
	m.confirmRemove = false
	m.formError = ""
	m.createName.Blur()
	m.createImage.Blur()
	m.shareTag.Blur()
	m.sharePath.Blur()
	m.portBind.Blur()
	m.portGuest.Blur()
	m.shareReplace = false
}

func (m *sandboxTUIModel) resizeInputs() {
	width, _ := m.dialogSize(tuiCreateDialog)
	fieldWidth := maxInt(12, width-10)
	m.createName.SetWidth(fieldWidth)
	m.createImage.SetWidth(fieldWidth)
	shareWidth, _ := m.dialogSize(tuiShareAddDialog)
	shareFieldWidth := maxInt(12, shareWidth-10)
	m.shareTag.SetWidth(shareFieldWidth)
	m.sharePath.SetWidth(shareFieldWidth)
	portWidth, _ := m.dialogSize(tuiPortPublishDialog)
	portFieldWidth := maxInt(12, portWidth-10)
	m.portBind.SetWidth(portFieldWidth)
	m.portGuest.SetWidth(portFieldWidth)
}

func (m *sandboxTUIModel) applyInputTheme() {
	theme := tuiThemeFor(m.dark)
	styles := textinput.DefaultStyles(m.dark)
	styles.Focused.Text = lipgloss.NewStyle().Foreground(theme.text)
	styles.Focused.Placeholder = lipgloss.NewStyle().Foreground(theme.muted)
	styles.Focused.Prompt = lipgloss.NewStyle().Foreground(theme.accent)
	styles.Blurred.Text = lipgloss.NewStyle().Foreground(theme.secondary)
	styles.Blurred.Placeholder = lipgloss.NewStyle().Foreground(theme.muted)
	styles.Blurred.Prompt = lipgloss.NewStyle().Foreground(theme.muted)
	styles.Cursor.Color = theme.accent
	m.createName.SetStyles(styles)
	m.createImage.SetStyles(styles)
	m.shareTag.SetStyles(styles)
	m.sharePath.SetStyles(styles)
	m.portBind.SetStyles(styles)
	m.portGuest.SetStyles(styles)
	m.spinner.Style = lipgloss.NewStyle().Foreground(theme.accent)
}

func (m *sandboxTUIModel) updateMouseClick(mouse tea.Mouse) (tea.Model, tea.Cmd) {
	if mouse.Button != tea.MouseLeft {
		return m, nil
	}
	if m.dialog == tuiNoDialog && m.toast != nil && m.toastBounds(tuiThemeFor(m.dark)).contains(mouse.X, mouse.Y) {
		m.toast = nil
		return m, nil
	}
	if m.dialog != tuiNoDialog {
		bounds := m.dialogBounds(m.dialog)
		if !bounds.contains(mouse.X, mouse.Y) {
			m.closeDialog()
			return m, nil
		}
		// Every dialog has a close glyph in its title row (the dialog has one
		// row of border and one row of vertical padding above it).
		if mouse.Y >= bounds.y+1 && mouse.Y <= bounds.y+3 && mouse.X >= bounds.x+bounds.w-6 {
			m.closeDialog()
			return m, nil
		}
		if (m.dialog == tuiRemoveDialog || m.dialog == tuiShareRemoveDialog) && mouse.Y == bounds.y+bounds.h-3 {
			if mouse.X >= bounds.x+bounds.w/2 {
				m.confirmRemove = true
				if m.dialog == tuiShareRemoveDialog {
					return m.removeSelectedShare()
				}
				return m.removeSelected()
			}
			m.closeDialog()
			return m, nil
		}
		if m.dialog == tuiCreateDialog {
			relY := mouse.Y - bounds.y
			switch {
			case relY >= 5 && relY <= 7:
				return m, m.focusCreate(0)
			case relY >= 9 && relY <= 11:
				return m, m.focusCreate(1)
			case relY >= 13 && relY <= 14:
				m.createFocus = 2
				if m.createRuntime == "runsc" {
					m.createRuntime = "crun"
				} else {
					m.createRuntime = "runsc"
				}
				return m, nil
			case relY >= 15 && relY <= 16:
				m.createFocus = 3
				m.cycleCreateKernel(1)
				return m, nil
			case relY >= bounds.h-4 && mouse.X >= bounds.x+bounds.w/2:
				m.createFocus = 4
				return m.submitCreate()
			}
		}
		if m.dialog == tuiShareAddDialog {
			relY := mouse.Y - bounds.y
			switch {
			case relY >= 6 && relY <= 8:
				return m, m.focusShare(0)
			case relY >= 10 && relY <= 12:
				return m, m.focusShare(1)
			case relY >= 13 && relY <= 14:
				m.shareFocus = 2
				m.shareRO = !m.shareRO
			case relY >= bounds.h-4 && mouse.X >= bounds.x+bounds.w/2:
				m.shareFocus = 3
				return m.submitShare()
			}
		}
		if m.dialog == tuiPortPublishDialog {
			relY := mouse.Y - bounds.y
			switch {
			case relY >= 6 && relY <= 8:
				return m, m.focusPort(0)
			case relY >= 10 && relY <= 12:
				return m, m.focusPort(1)
			case relY >= 13 && relY <= 14:
				m.portFocus = 2
				m.portUDP = !m.portUDP
			case relY >= bounds.h-5 && mouse.X >= bounds.x+bounds.w/2:
				m.portFocus = 3
				return m.submitPort()
			}
		}
		if m.dialog == tuiPortUnpublishDialog && mouse.Y == bounds.y+bounds.h-3 {
			if mouse.X >= bounds.x+bounds.w/2 {
				m.confirmRemove = true
				return m.unpublishSelectedPort()
			}
			m.closeDialog()
			return m, nil
		}
		return m, nil
	}

	// Dashboard tabs are both keyboard-addressable (1-4 / tab) and clickable.
	if mouse.Y == tuiMenuHeight {
		tabs := m.tabRects(m.dashboardLayout().width)
		for _, tab := range tabs {
			if mouse.X >= tab.x && mouse.X < tab.x+tab.w {
				if len(tabs) == 1 {
					if mouse.X < tab.x+tab.w/2 {
						m.cyclePage(-1)
					} else {
						m.cyclePage(1)
					}
				} else {
					m.setPage(tab.page)
				}
				return m, nil
			}
		}
	}

	// The menu bar exposes the same primary actions as the reference CLI:
	// New and Help are both keyboard shortcuts and mouse targets.
	if mouse.Y == 1 {
		switch {
		case mouse.X >= m.width-9:
			m.dialog = tuiHelpDialog
			return m, nil
		case mouse.X >= m.width-20 && m.busyAction == "":
			return m, m.openCreateDialog()
		}
	}
	if m.busyAction != "" {
		return m, nil
	}

	layout := m.dashboardLayout()
	if m.page != tuiSandboxesPage {
		rowY := layout.contentY + tuiTableHeaderHeight
		if mouse.Y >= rowY && mouse.Y < rowY+m.tableVisibleRows() {
			index := mouse.Y - rowY
			cursor, scroll, count := m.tableState()
			if cursor != nil {
				index += *scroll
				if index >= 0 && index < count {
					*cursor = index
					m.ensureTableCursorVisible()
				}
			}
		}
		return m, nil
	}

	index, card, ok := layout.cardAt(mouse.X, mouse.Y, m.scrollRow, m.entryCount())
	if !ok {
		return m, nil
	}

	wasSelected := index == m.cursor
	m.setCursor(index)
	localY := mouse.Y - card.y
	if wasSelected && localY == card.h-2 {
		return m.cardActionAt(mouse.X, card)
	}

	doubleClick := index == m.lastClickIndex && time.Since(m.lastClickAt) <= 450*time.Millisecond
	m.lastClickIndex, m.lastClickAt = index, time.Now()
	if doubleClick {
		m.lastClickAt = time.Time{}
		return m.primaryAction()
	}
	return m, nil
}

func (m *sandboxTUIModel) cardActionAt(x int, card tuiRect) (tea.Model, tea.Cmd) {
	if m.onNewCard() {
		return m, m.openCreateDialog()
	}
	selected := m.selected()
	if selected == nil {
		return m, nil
	}
	actions := []string{"primary", "info", "delete"}
	if selected.State == tuiRunning {
		actions = []string{"primary", "toggle", "info", "delete"}
	}
	innerX := clampInt(x-card.x-2, 0, maxInt(0, card.w-5))
	segment := maxInt(1, (card.w-4)/len(actions))
	index := minInt(len(actions)-1, innerX/segment)
	switch actions[index] {
	case "primary":
		return m.primaryAction()
	case "toggle":
		return m.toggleSelected()
	case "info":
		m.dialog = tuiInfoDialog
	case "delete":
		m.dialog = tuiRemoveDialog
		m.confirmRemove = false
	}
	return m, nil
}

func (m *sandboxTUIModel) updateMouseWheel(mouse tea.Mouse) (tea.Model, tea.Cmd) {
	if m.dialog != tuiNoDialog || m.busyAction != "" {
		return m, nil
	}
	m.lastClickAt = time.Time{}
	if m.page != tuiSandboxesPage {
		switch mouse.Button {
		case tea.MouseWheelUp:
			m.moveTableCursor(-1)
		case tea.MouseWheelDown:
			m.moveTableCursor(1)
		}
		return m, nil
	}
	switch mouse.Button {
	case tea.MouseWheelUp:
		m.moveCursor(0, -1)
	case tea.MouseWheelDown:
		m.moveCursor(0, 1)
	}
	return m, nil
}
