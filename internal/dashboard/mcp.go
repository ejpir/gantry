package dashboard

import (
	"strings"

	dashboardapi "github.com/ejpir/gantry/internal/dashboard/api"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
)

const mcpRemoteSubmitFocus = 9

func (m *sandboxTUIModel) openMCPRemoteDialog(edit bool) tea.Cmd {
	preferred := ""
	if row := m.selectedMCPServer(); row != nil {
		preferred = row.Sandbox
	}
	if !m.mcpSandbox.ResetWhere(m.sandboxes, preferred, func(sandbox tuiSandbox) bool {
		return sandbox.State != tuiStarting
	}) {
		return m.showToast(tuiToastInfo, "No eligible sandbox", "Create a sandbox or wait for startup to finish before configuring MCP.")
	}
	m.dialog = tuiMCPRemoteDialog
	m.dialogScroll = 0
	m.formError = ""
	m.mcpEditing = edit
	m.mcpName.Reset()
	m.mcpURL.Reset()
	m.mcpAuthKind = ""
	m.mcpAuthHeader.Reset()
	m.mcpAuthRef.Reset()
	m.mcpAllow.Reset()
	m.mcpDeny.Reset()
	m.mcpRedact.Reset()
	if edit {
		row := m.selectedMCPServer()
		if row == nil || row.Type != "remote" || row.Error != "" {
			m.closeDialog()
			return nil
		}
		m.mcpName.SetValue(row.Name)
		m.mcpURL.SetValue(row.URL)
		m.mcpAuthKind = row.AuthKind
		m.mcpAuthHeader.SetValue(row.AuthHeader)
		m.mcpAuthRef.SetValue(row.AuthRef)
		m.mcpAllow.SetValue(strings.Join(row.Allow, ","))
		m.mcpDeny.SetValue(strings.Join(row.Deny, ","))
		m.mcpRedact.SetValue(strings.Join(row.Redact, ","))
	}
	m.resizeInputs()
	if edit {
		return m.focusMCPRemote(2)
	}
	return m.focusMCPRemote(0)
}

func (m *sandboxTUIModel) updateMCPRemoteDialogKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	if m.mcpFocus == 0 && !m.mcpEditing && m.mcpSandbox.HandleKey(msg.String()) {
		return m, nil
	}
	switch msg.String() {
	case "esc":
		m.closeDialog()
		return m, nil
	case "tab", "down":
		return m, m.moveMCPRemoteFocus(1)
	case "shift+tab", "up":
		return m, m.moveMCPRemoteFocus(-1)
	case "left", "h":
		if m.mcpFocus == 3 {
			m.cycleMCPAuth(-1)
			return m, nil
		}
	case "right", "l", " ", "space":
		if m.mcpFocus == 3 {
			m.cycleMCPAuth(1)
			return m, nil
		}
	case "ctrl+enter":
		return m.submitMCPRemote()
	case "enter":
		if m.mcpFocus != mcpRemoteSubmitFocus {
			return m, m.moveMCPRemoteFocus(1)
		}
		return m.submitMCPRemote()
	}
	var cmd tea.Cmd
	switch m.mcpFocus {
	case 1:
		m.mcpName, cmd = m.mcpName.Update(msg)
	case 2:
		m.mcpURL, cmd = m.mcpURL.Update(msg)
	case 4:
		m.mcpAuthRef, cmd = m.mcpAuthRef.Update(msg)
	case 5:
		m.mcpAuthHeader, cmd = m.mcpAuthHeader.Update(msg)
	case 6:
		m.mcpAllow, cmd = m.mcpAllow.Update(msg)
	case 7:
		m.mcpDeny, cmd = m.mcpDeny.Update(msg)
	case 8:
		m.mcpRedact, cmd = m.mcpRedact.Update(msg)
	}
	m.formError = ""
	return m, cmd
}

func (m *sandboxTUIModel) moveMCPRemoteFocus(delta int) tea.Cmd {
	focus := m.mcpFocus
	for {
		focus = (focus + delta + mcpRemoteSubmitFocus + 1) % (mcpRemoteSubmitFocus + 1)
		if !m.mcpEditing || (focus != 0 && focus != 1) {
			return m.focusMCPRemote(focus)
		}
	}
}

func (m *sandboxTUIModel) focusMCPRemote(index int) tea.Cmd {
	m.mcpFocus = clampInt(index, 0, mcpRemoteSubmitFocus)
	m.mcpSandbox.open = false
	m.mcpName.Blur()
	m.mcpURL.Blur()
	m.mcpAuthRef.Blur()
	m.mcpAuthHeader.Blur()
	m.mcpAllow.Blur()
	m.mcpDeny.Blur()
	m.mcpRedact.Blur()
	m.ensureDialogFocusVisible()
	if m.mcpFocus == mcpRemoteSubmitFocus {
		m.dialogScroll = m.dialogMaxScroll()
	}
	switch m.mcpFocus {
	case 1:
		return m.mcpName.Focus()
	case 2:
		return m.mcpURL.Focus()
	case 4:
		return m.mcpAuthRef.Focus()
	case 5:
		return m.mcpAuthHeader.Focus()
	case 6:
		return m.mcpAllow.Focus()
	case 7:
		return m.mcpDeny.Focus()
	case 8:
		return m.mcpRedact.Focus()
	default:
		return nil
	}
}

func (m *sandboxTUIModel) cycleMCPAuth(delta int) {
	choices := []string{"", "bearer", "header", "custody"}
	index := 0
	for i, choice := range choices {
		if choice == m.mcpAuthKind {
			index = i
			break
		}
	}
	m.mcpAuthKind = choices[(index+delta+len(choices))%len(choices)]
	if m.mcpAuthKind == "" {
		m.mcpAuthHeader.Reset()
		m.mcpAuthRef.Reset()
	} else if m.mcpAuthKind != "header" {
		m.mcpAuthHeader.Reset()
	}
	m.formError = ""
}

func splitMCPDialogList(raw string) []string {
	var values []string
	for _, value := range strings.Split(raw, ",") {
		if value = strings.TrimSpace(value); value != "" {
			values = append(values, value)
		}
	}
	return values
}

func (m *sandboxTUIModel) mcpRemoteRequest() dashboardapi.MCPRemoteRequest {
	return dashboardapi.MCPRemoteRequest{
		Sandbox: m.mcpSandbox.Value(), Name: strings.TrimSpace(m.mcpName.Value()), URL: strings.TrimSpace(m.mcpURL.Value()),
		AuthKind: m.mcpAuthKind, AuthHeader: strings.TrimSpace(m.mcpAuthHeader.Value()), AuthRef: strings.TrimSpace(m.mcpAuthRef.Value()),
		Allow: splitMCPDialogList(m.mcpAllow.Value()), Deny: splitMCPDialogList(m.mcpDeny.Value()),
		Redact: splitMCPDialogList(m.mcpRedact.Value()), Replace: m.mcpEditing,
	}
}

func (m *sandboxTUIModel) submitMCPRemote() (tea.Model, tea.Cmd) {
	request := m.mcpRemoteRequest()
	if err := m.service.ValidateMCPRemote(request); err != nil {
		m.formError = err.Error()
		focus := map[string]int{
			"sandbox": 0, "name": 1, "url": 2, "auth": 3, "auth_ref": 4,
			"auth_header": 5, "allow": 6, "deny": 7, "redact": 8,
		}[dashboardErrorField(err)]
		if m.mcpEditing && focus < 2 {
			focus = 2
		}
		return m, m.focusMCPRemote(focus)
	}
	target := m.sandboxNamed(request.Sandbox)
	running := target != nil && target.State == tuiRunning
	m.closeDialog()
	m.busyAction = "mcp configure"
	m.busyName = request.Sandbox + "/" + request.Name
	return m, tea.Batch(configureMCPRemoteCmd(m.service, request, running), m.ensureAnimation())
}

func (m *sandboxTUIModel) openMCPFilesystemDialog() tea.Cmd {
	preferred := ""
	if row := m.selectedMCPServer(); row != nil {
		preferred = row.Sandbox
	}
	if !m.mcpSandbox.ResetWhere(m.sandboxes, preferred, func(sandbox tuiSandbox) bool {
		return sandbox.State != tuiStarting
	}) {
		return m.showToast(tuiToastInfo, "No eligible sandbox", "Create a sandbox or wait for startup to finish before configuring MCP.")
	}
	m.dialog = tuiMCPFilesystemDialog
	m.dialogScroll = 0
	m.formError = ""
	m.syncMCPFilesystemFields()
	m.resizeInputs()
	return m.focusMCPFilesystem(0)
}

func (m *sandboxTUIModel) syncMCPFilesystemFields() {
	m.mcpFSRoot.SetValue("/")
	m.mcpFSUser.SetValue("nobody")
	for _, row := range m.mcpServers {
		if row.Sandbox == m.mcpSandbox.Value() && row.Type == "local" && row.Error == "" {
			m.mcpFSRoot.SetValue(row.Root)
			m.mcpFSUser.SetValue(row.User)
			return
		}
	}
}

func (m *sandboxTUIModel) updateMCPFilesystemDialogKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	if m.mcpFSFocus == 0 {
		before := m.mcpSandbox.Value()
		if m.mcpSandbox.HandleKey(msg.String()) {
			if before != m.mcpSandbox.Value() {
				m.syncMCPFilesystemFields()
			}
			return m, nil
		}
	}
	switch msg.String() {
	case "esc":
		m.closeDialog()
		return m, nil
	case "tab", "down":
		return m, m.focusMCPFilesystem((m.mcpFSFocus + 1) % 4)
	case "shift+tab", "up":
		return m, m.focusMCPFilesystem((m.mcpFSFocus + 3) % 4)
	case "ctrl+enter":
		return m.submitMCPFilesystem()
	case "enter":
		if m.mcpFSFocus < 3 {
			return m, m.focusMCPFilesystem(m.mcpFSFocus + 1)
		}
		return m.submitMCPFilesystem()
	}
	var cmd tea.Cmd
	switch m.mcpFSFocus {
	case 1:
		m.mcpFSRoot, cmd = m.mcpFSRoot.Update(msg)
	case 2:
		m.mcpFSUser, cmd = m.mcpFSUser.Update(msg)
	}
	m.formError = ""
	return m, cmd
}

func (m *sandboxTUIModel) focusMCPFilesystem(index int) tea.Cmd {
	m.mcpFSFocus = clampInt(index, 0, 3)
	m.mcpSandbox.open = false
	m.mcpFSRoot.Blur()
	m.mcpFSUser.Blur()
	m.ensureDialogFocusVisible()
	if m.mcpFSFocus == 1 {
		return m.mcpFSRoot.Focus()
	}
	if m.mcpFSFocus == 2 {
		return m.mcpFSUser.Focus()
	}
	return nil
}

func (m *sandboxTUIModel) submitMCPFilesystem() (tea.Model, tea.Cmd) {
	request := dashboardapi.MCPFilesystemRequest{
		Sandbox: m.mcpSandbox.Value(), Root: strings.TrimSpace(m.mcpFSRoot.Value()), User: strings.TrimSpace(m.mcpFSUser.Value()),
	}
	if err := m.service.ValidateMCPFilesystem(request); err != nil {
		m.formError = err.Error()
		if dashboardErrorField(err) == "sandbox" {
			return m, m.focusMCPFilesystem(0)
		}
		if dashboardErrorField(err) == "user" {
			return m, m.focusMCPFilesystem(2)
		}
		return m, m.focusMCPFilesystem(1)
	}
	target := m.sandboxNamed(request.Sandbox)
	running := target != nil && target.State == tuiRunning
	m.closeDialog()
	m.busyAction = "mcp filesystem"
	m.busyName = request.Sandbox + "/fs"
	return m, tea.Batch(configureMCPFilesystemCmd(m.service, request, running), m.ensureAnimation())
}

func (m *sandboxTUIModel) removeSelectedMCPRemote() (tea.Model, tea.Cmd) {
	row := m.selectedMCPServer()
	if row == nil || row.Type != "remote" || row.Error != "" {
		m.closeDialog()
		return m, nil
	}
	target := m.sandboxNamed(row.Sandbox)
	running := target != nil && target.State == tuiRunning
	copyRow := *row
	m.closeDialog()
	m.busyAction = "mcp remove"
	m.busyName = row.Sandbox + "/" + row.Name
	return m, tea.Batch(removeMCPRemoteCmd(m.service, copyRow, running), m.ensureAnimation())
}

func (m sandboxTUIModel) renderMCPRemoteDialog(theme tuiTheme, width int) string {
	title, button := "Add Remote MCP Server", "Add server"
	description := "Save a streamable-HTTP upstream. Running sandboxes require a restart."
	if m.mcpEditing {
		title, button = "Edit Remote MCP Server", "Save server"
	}
	header := m.dialogHeader(theme, title, width)
	locked := lipgloss.NewStyle().Foreground(theme.secondary)
	sandboxField := m.mcpSandbox.View(theme, width, m.mcpFocus == 0 && !m.mcpEditing)
	nameField := renderInputField(theme, m.mcpName.View(), width, m.mcpFocus == 1 && !m.mcpEditing)
	if m.mcpEditing {
		sandboxField = renderInputField(theme, locked.Render(m.mcpSandbox.Value()+"  (fixed)"), width, false)
		nameField = renderInputField(theme, locked.Render(m.mcpName.Value()+"  (fixed)"), width, false)
	}
	auth := defaultText(m.mcpAuthKind, "none")
	authLine := formLabel(theme, "Authentication", m.mcpFocus == 3) + "  " + locked.Render(auth+"  (space cycles)")
	fields := []string{
		formLabel(theme, "Sandbox", m.mcpFocus == 0 && !m.mcpEditing) + "\n" + sandboxField,
		formLabel(theme, "Name", m.mcpFocus == 1 && !m.mcpEditing) + "\n" + nameField,
		formLabel(theme, "HTTPS URL", m.mcpFocus == 2) + "\n" + renderInputField(theme, m.mcpURL.View(), width, m.mcpFocus == 2),
		authLine,
		formLabel(theme, "Secret / provider reference", m.mcpFocus == 4) + "\n" + renderInputField(theme, m.mcpAuthRef.View(), width, m.mcpFocus == 4),
		formLabel(theme, "Header name", m.mcpFocus == 5) + locked.Render("  header auth only") + "\n" + renderInputField(theme, m.mcpAuthHeader.View(), width, m.mcpFocus == 5),
		formLabel(theme, "Allow tool globs", m.mcpFocus == 6) + "\n" + renderInputField(theme, m.mcpAllow.View(), width, m.mcpFocus == 6),
		formLabel(theme, "Deny tool globs", m.mcpFocus == 7) + "\n" + renderInputField(theme, m.mcpDeny.View(), width, m.mcpFocus == 7),
		formLabel(theme, "Additional redact secret names", m.mcpFocus == 8) + "\n" + renderInputField(theme, m.mcpRedact.View(), width, m.mcpFocus == 8),
	}
	errorLine := ""
	if m.formError != "" {
		errorLine = lipgloss.NewStyle().Foreground(theme.error).Render(truncateText(m.formError, width))
	}
	buttons := alignRight(renderDialogButton(theme, button, m.mcpFocus == mcpRemoteSubmitFocus, false), width)
	hint := lipgloss.NewStyle().Foreground(theme.muted).Render("tab next  •  space auth  •  ctrl+enter save  •  esc cancel")
	gap := m.formSectionGap()
	return header + "\n" + lipgloss.NewStyle().Foreground(theme.secondary).Render(description) + gap + strings.Join(fields, gap) + "\n" + renderFormFooter(errorLine, buttons, hint)
}

func (m sandboxTUIModel) renderMCPFilesystemDialog(theme tuiTheme, width int) string {
	header := m.dialogHeader(theme, "Filesystem MCP Server", width)
	description := lipgloss.NewStyle().Foreground(theme.secondary).Render("Configure the built-in read-only guest filesystem server. Restart to apply changes to a running sandbox.")
	fields := []string{
		formLabel(theme, "Sandbox", m.mcpFSFocus == 0) + "\n" + m.mcpSandbox.View(theme, width, m.mcpFSFocus == 0),
		formLabel(theme, "Guest root", m.mcpFSFocus == 1) + "\n" + renderInputField(theme, m.mcpFSRoot.View(), width, m.mcpFSFocus == 1),
		formLabel(theme, "Unprivileged guest user", m.mcpFSFocus == 2) + "\n" + renderInputField(theme, m.mcpFSUser.View(), width, m.mcpFSFocus == 2),
	}
	errorLine := ""
	if m.formError != "" {
		errorLine = lipgloss.NewStyle().Foreground(theme.error).Render(truncateText(m.formError, width))
	}
	buttons := alignRight(renderDialogButton(theme, "Save", m.mcpFSFocus == 3, false), width)
	hint := lipgloss.NewStyle().Foreground(theme.muted).Render("tab next  •  ctrl+enter save  •  esc cancel")
	gap := m.formSectionGap()
	return header + "\n" + description + gap + strings.Join(fields, gap) + "\n" + renderFormFooter(errorLine, buttons, hint)
}

func (m *sandboxTUIModel) updateMCPRemoteDialogMouse(mouse tea.Mouse, bounds tuiRect) (tea.Model, tea.Cmd) {
	button := "Add server"
	if m.mcpEditing {
		button = "Save server"
	}
	if m.dialogButtonHit(mouse, bounds, button) {
		m.mcpFocus = mcpRemoteSubmitFocus
		return m.submitMCPRemote()
	}
	fields := []string{"Sandbox", "Name", "HTTPS URL", "Authentication", "Secret / provider reference", "Header name", "Allow tool globs", "Deny tool globs", "Additional redact secret names"}
	for focus, label := range fields {
		if m.mcpEditing && (focus == 0 || focus == 1) {
			continue
		}
		if !m.mcpDialogFieldHit(mouse, bounds, label) {
			continue
		}
		cmd := m.focusMCPRemote(focus)
		if focus == 0 {
			m.mcpSandbox.Toggle()
		}
		if focus == 3 {
			m.cycleMCPAuth(1)
		}
		return m, cmd
	}
	return m, nil
}

func (m *sandboxTUIModel) updateMCPFilesystemDialogMouse(mouse tea.Mouse, bounds tuiRect) (tea.Model, tea.Cmd) {
	if m.dialogButtonHit(mouse, bounds, "Save") {
		m.mcpFSFocus = 3
		return m.submitMCPFilesystem()
	}
	for focus, label := range []string{"Sandbox", "Guest root", "Unprivileged guest user"} {
		if !m.mcpDialogFieldHit(mouse, bounds, label) {
			continue
		}
		cmd := m.focusMCPFilesystem(focus)
		if focus == 0 {
			m.mcpSandbox.Toggle()
		}
		return m, cmd
	}
	return m, nil
}

func (m sandboxTUIModel) mcpDialogFieldHit(mouse tea.Mouse, bounds tuiRect, label string) bool {
	lines := strings.Split(ansi.Strip(m.renderDialog(tuiThemeFor(m.dark))), "\n")
	for row, line := range lines {
		if strings.Contains(line, label) {
			return mouse.X > bounds.x && mouse.X < bounds.x+bounds.w-1 && mouse.Y >= bounds.y+row && mouse.Y <= bounds.y+row+1
		}
	}
	return false
}

func (m sandboxTUIModel) renderMCPRemoveDialog(theme tuiTheme, width int) string {
	header := m.dialogHeader(theme, "Remove Remote MCP Server", width)
	row := m.selectedMCPServer()
	if row == nil || row.Type != "remote" {
		return header + "\n\n" + lipgloss.NewStyle().Foreground(theme.muted).Render("No remote MCP server selected.")
	}
	value := lipgloss.NewStyle().Bold(true).Foreground(theme.text).Render(row.Sandbox + " / " + row.Name)
	detail := lipgloss.NewStyle().Foreground(theme.secondary).Render(row.URL)
	warning := lipgloss.NewStyle().Foreground(theme.warning).Render("The live MCP worker is immutable; restart a running sandbox to withdraw this server.")
	cancel := renderDialogButton(theme, "Cancel", !m.confirmRemove, false)
	remove := renderDialogButton(theme, "Remove", m.confirmRemove, true)
	buttons := alignRight(cancel+"  "+remove, width)
	hint := lipgloss.NewStyle().Foreground(theme.muted).Render("←/→ choose  •  enter confirm")
	return header + "\n\n" + value + "\n" + detail + "\n\n" + warning + "\n\n" + renderConfirmationFooter(buttons, hint)
}
