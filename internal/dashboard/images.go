package dashboard

// images.go — the IMAGES tab: the cached OCI image store plus the registry
// credentials used to pull into it. One page, two sections; s switches.

import (
	"fmt"
	"strings"
	"time"

	dashboardapi "github.com/ejpir/gantry/internal/dashboard/api"
	"github.com/ejpir/gantry/internal/secret"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

// ---------------- images section ----------------

func (m sandboxTUIModel) renderImagesView(theme tuiTheme, layout tuiDashboardLayout) string {
	if m.imageSection == tuiImageSectionCredentials {
		return m.renderStandardTable(theme, layout, tuiImagesPage,
			"Loading registry credentials…", "No registries known", "Press a to store a registry login.")
	}
	return m.renderStandardTable(theme, layout, tuiImagesPage,
		"Loading image store…", "No cached images", "Press p to pull an image reference, or start a sandbox with -image.")
}

func (m sandboxTUIModel) renderImagesHeader(theme tuiTheme, width int) string {
	style := lipgloss.NewStyle().Bold(true).Foreground(theme.muted)
	var line string
	switch {
	case width >= 96:
		refWidth := maxInt(16, width-56)
		line = tableCell("", 2) + " " + tableCell("REF", refWidth) + " " + tableCell("DIGEST", 21) + " " +
			tableCell("ARCH", 7) + " " + tableCell("SIZE", 9) + " " + tableCell("CREATED", 12)
	case width >= 56:
		refWidth := maxInt(12, width-24)
		line = tableCell("", 2) + " " + tableCell("REF", refWidth) + " " + tableCell("ARCH", 7) + " " + tableCell("SIZE", 9)
	default:
		line = tableCell("", 2) + " " + tableCell("IMAGE", maxInt(1, width-3))
	}
	return style.Render(truncateANSI(line, width))
}

func (m sandboxTUIModel) renderImageRow(theme tuiTheme, row tuiImageRow, width int) string {
	inUse := lipgloss.NewStyle().Foreground(theme.success).Render("●")
	if !row.InUse {
		inUse = lipgloss.NewStyle().Foreground(theme.muted).Render("○")
	}
	switch {
	case width >= 96:
		refWidth := maxInt(16, width-56)
		return tableCell(inUse, 2) + " " + tableCell(row.Ref, refWidth) + " " + tableCell(shortImageDigest(row.Digest), 21) + " " +
			tableCell(defaultText(row.Arch, "?"), 7) + " " + tableCell(formatBytes(uint64(maxInt(0, int(row.Size)))), 9) + " " +
			tableCell(formatImageCreated(row.Created), 12)
	case width >= 56:
		refWidth := maxInt(12, width-24)
		return tableCell(inUse, 2) + " " + tableCell(row.Ref, refWidth) + " " + tableCell(defaultText(row.Arch, "?"), 7) + " " +
			tableCell(formatBytes(uint64(maxInt(0, int(row.Size)))), 9)
	default:
		return tableCell(inUse, 2) + " " + tableCell(row.Ref, maxInt(1, width-3))
	}
}

func (m sandboxTUIModel) renderImageDetail(theme tuiTheme, width int) []string {
	if m.imageCursor < 0 || m.imageCursor >= len(m.images) || m.tableDetailHeight() == 0 {
		return nil
	}
	row := m.images[m.imageCursor]
	title := lipgloss.NewStyle().Bold(true).Foreground(theme.text).Render(row.Ref) + "  " +
		lipgloss.NewStyle().Foreground(theme.muted).Render(defaultText(row.Arch, "?")+"  •  "+
			formatBytes(uint64(maxInt(0, int(row.Size))))+"  •  built "+defaultText(formatImageCreated(row.Created), "unknown"))
	command := strings.TrimSpace(strings.Join(append(append([]string{}, row.Entrypoint...), row.Cmd...), " "))
	if command == "" {
		command = "default shell"
	}
	usage := lipgloss.NewStyle().Foreground(theme.muted).Render("not referenced by a sandbox — u prunes unused images")
	if row.InUse {
		usage = lipgloss.NewStyle().Foreground(theme.success).Render("in use by a sandbox")
	}
	return []string{
		m.renderTableSeparator(theme, width),
		title,
		lipgloss.NewStyle().Foreground(theme.muted).Render("digest  ") + lipgloss.NewStyle().Foreground(theme.secondary).Render(row.Digest),
		lipgloss.NewStyle().Foreground(theme.muted).Render("config  ") + lipgloss.NewStyle().Foreground(theme.secondary).Render(
			fmt.Sprintf("user %s  •  workdir %s  •  %d env", defaultText(row.User, "0 (root)"), defaultText(row.WorkingDir, "/"), row.EnvCount)),
		lipgloss.NewStyle().Foreground(theme.muted).Render("run     ") + lipgloss.NewStyle().Foreground(theme.secondary).Render(command) + "  " + usage,
	}
}

func shortImageDigest(digest string) string {
	digest = strings.TrimPrefix(digest, "sha256:")
	if len(digest) > 19 {
		return digest[:19] + "…"
	}
	return digest
}

func formatImageCreated(created string) string {
	parsed, err := time.Parse(time.RFC3339, created)
	if err != nil {
		return truncateText(created, 12)
	}
	return parsed.Local().Format("Jan 02 15:04")
}

// ---------------- credentials section ----------------

func (m sandboxTUIModel) renderRegistriesHeader(theme tuiTheme, width int) string {
	style := lipgloss.NewStyle().Bold(true).Foreground(theme.muted)
	var line string
	if width >= 72 {
		sourceWidth := maxInt(16, width-53)
		line = tableCell("REGISTRY", 20) + " " + tableCell("USERNAME", 14) + " " + tableCell("SOURCE", sourceWidth) + " " + tableCell("SECRET", 7)
	} else {
		line = tableCell("REGISTRY", maxInt(12, width-10)) + " " + tableCell("SECRET", 8)
	}
	return style.Render(truncateANSI(line, width))
}

func (m sandboxTUIModel) renderRegistryRow(theme tuiTheme, row tuiRegistryRow, width int) string {
	username := row.Username
	if username == "" {
		username = "(anonymous)"
	}
	secretState := lipgloss.NewStyle().Foreground(theme.muted).Render("no")
	if row.HasSecret {
		secretState = lipgloss.NewStyle().Foreground(theme.success).Render("yes")
	}
	if width >= 72 {
		sourceWidth := maxInt(16, width-53)
		source := row.Source
		if !row.HasSecret {
			source = defaultText(row.Source, "anonymous")
		}
		return tableCell(row.Registry, 20) + " " + tableCell(username, 14) + " " + tableCell(source, sourceWidth) + " " + tableCell(secretState, 7)
	}
	return tableCell(row.Registry, maxInt(12, width-10)) + " " + tableCell(secretState, 8)
}

func (m sandboxTUIModel) renderRegistryDetail(theme tuiTheme, width int) []string {
	if m.registryCursor < 0 || m.registryCursor >= len(m.registries) || m.tableDetailHeight() == 0 {
		return nil
	}
	row := m.registries[m.registryCursor]
	title := lipgloss.NewStyle().Bold(true).Foreground(theme.text).Render(row.Registry)
	source := "anonymous pulls"
	if row.HasSecret {
		source = "credential from " + defaultText(row.Source, "unknown source")
	}
	hint := "press a to store a login"
	if row.HasSecret {
		hint = "press d to log out (erases the stored credential)"
	}
	return []string{
		m.renderTableSeparator(theme, width),
		title + "  " + lipgloss.NewStyle().Foreground(theme.secondary).Render(source),
		lipgloss.NewStyle().Foreground(theme.muted).Render("user    ") + lipgloss.NewStyle().Foreground(theme.secondary).Render(defaultText(row.Username, "—")),
		lipgloss.NewStyle().Foreground(theme.muted).Render("pulls authenticate on the host; credentials never enter a sandbox"),
		lipgloss.NewStyle().Foreground(theme.muted).Render(hint),
	}
}

// ---------------- pull dialog ----------------

const tuiImagePullSubmitFocus = 2

func (m *sandboxTUIModel) openImagePullDialog() tea.Cmd {
	m.dialog = tuiImagePullDialog
	m.dialogScroll = 0
	m.formError = ""
	m.pullRef.Reset()
	m.pullArch = "auto"
	m.resizeInputs()
	return m.focusImagePull(0)
}

func (m *sandboxTUIModel) focusImagePull(index int) tea.Cmd {
	m.pullFocus = clampInt(index, 0, tuiImagePullSubmitFocus)
	m.pullRef.Blur()
	m.ensureDialogFocusVisible()
	if m.pullFocus == 0 {
		return m.pullRef.Focus()
	}
	return nil
}

func (m *sandboxTUIModel) cycleImagePullArch(delta int) {
	choices := []string{"auto", "amd64", "arm64"}
	index := 0
	for i, choice := range choices {
		if choice == m.pullArch {
			index = i
			break
		}
	}
	m.pullArch = choices[(index+delta+len(choices))%len(choices)]
}

func (m *sandboxTUIModel) updateImagePullDialogKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.closeDialog()
		return m, nil
	case "tab", "down":
		return m, m.focusImagePull((m.pullFocus + 1) % (tuiImagePullSubmitFocus + 1))
	case "shift+tab", "up":
		return m, m.focusImagePull((m.pullFocus + tuiImagePullSubmitFocus) % (tuiImagePullSubmitFocus + 1))
	case "left", "h":
		if m.pullFocus == 1 {
			m.cycleImagePullArch(-1)
			return m, nil
		}
	case "right", "l", " ", "space":
		if m.pullFocus == 1 {
			m.cycleImagePullArch(1)
			return m, nil
		}
	case "ctrl+enter":
		return m.submitImagePull()
	case "enter":
		if m.pullFocus < tuiImagePullSubmitFocus {
			return m, m.focusImagePull(m.pullFocus + 1)
		}
		return m.submitImagePull()
	}
	var cmd tea.Cmd
	if m.pullFocus == 0 {
		m.pullRef, cmd = m.pullRef.Update(msg)
	}
	m.formError = ""
	return m, cmd
}

// imagePullArgv builds the CLI argv for the pull dialog. Kept separate from
// submitImagePull so tests can inspect it without spawning.
func (m *sandboxTUIModel) imagePullArgv(ref string) []string {
	argv := []string{"image", "pull"}
	if m.pullArch != "auto" {
		argv = append(argv, "-platform", "linux/"+m.pullArch)
	}
	return append(argv, ref)
}

func (m *sandboxTUIModel) submitImagePull() (tea.Model, tea.Cmd) {
	ref := strings.TrimSpace(m.pullRef.Value())
	if ref == "" {
		m.formError = "an image reference is required"
		return m, m.focusImagePull(0)
	}
	return m.beginAction("image pull", ref, m.imagePullArgv(ref), false)
}

// ---------------- registry login dialog ----------------

const tuiRegistryLoginSubmitFocus = 3

func (m *sandboxTUIModel) openRegistryLoginDialog() tea.Cmd {
	m.dialog = tuiRegistryLoginDialog
	m.dialogScroll = 0
	m.formError = ""
	m.loginRegistry.Reset()
	m.loginUsername.Reset()
	m.loginPassword.Reset()
	if row := m.selectedRegistry(); row != nil {
		m.loginRegistry.SetValue(row.Registry)
		if row.HasSecret {
			m.loginUsername.SetValue(row.Username)
		}
	}
	m.resizeInputs()
	if m.loginRegistry.Value() != "" {
		return m.focusRegistryLogin(1)
	}
	return m.focusRegistryLogin(0)
}

func (m *sandboxTUIModel) focusRegistryLogin(index int) tea.Cmd {
	m.loginFocus = clampInt(index, 0, tuiRegistryLoginSubmitFocus)
	m.loginRegistry.Blur()
	m.loginUsername.Blur()
	m.loginPassword.Blur()
	m.ensureDialogFocusVisible()
	switch m.loginFocus {
	case 0:
		return m.loginRegistry.Focus()
	case 1:
		return m.loginUsername.Focus()
	case 2:
		return m.loginPassword.Focus()
	default:
		return nil
	}
}

func (m *sandboxTUIModel) updateRegistryLoginDialogKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.closeDialog()
		return m, nil
	case "tab", "down":
		return m, m.focusRegistryLogin((m.loginFocus + 1) % (tuiRegistryLoginSubmitFocus + 1))
	case "shift+tab", "up":
		return m, m.focusRegistryLogin((m.loginFocus + tuiRegistryLoginSubmitFocus) % (tuiRegistryLoginSubmitFocus + 1))
	case "ctrl+enter":
		return m.submitRegistryLogin()
	case "enter":
		if m.loginFocus < tuiRegistryLoginSubmitFocus {
			return m, m.focusRegistryLogin(m.loginFocus + 1)
		}
		return m.submitRegistryLogin()
	}
	var cmd tea.Cmd
	switch m.loginFocus {
	case 0:
		m.loginRegistry, cmd = m.loginRegistry.Update(msg)
	case 1:
		m.loginUsername, cmd = m.loginUsername.Update(msg)
	case 2:
		m.loginPassword, cmd = m.loginPassword.Update(msg)
	}
	m.formError = ""
	return m, cmd
}

func (m *sandboxTUIModel) submitRegistryLogin() (tea.Model, tea.Cmd) {
	request := dashboardapi.RegistryLoginRequest{
		Registry: strings.TrimSpace(m.loginRegistry.Value()),
		Username: strings.TrimSpace(m.loginUsername.Value()),
		Secret:   secret.Value(m.loginPassword.Value()),
	}
	if err := m.service.ValidateRegistryLogin(request); err != nil {
		m.formError = err.Error()
		switch dashboardErrorField(err) {
		case "registry":
			return m, m.focusRegistryLogin(0)
		case "username":
			return m, m.focusRegistryLogin(1)
		default:
			return m, m.focusRegistryLogin(2)
		}
	}
	m.loginPassword.Reset()
	m.closeDialog()
	m.busyAction = "registry login"
	m.busyName = request.Registry
	return m, tea.Batch(storeRegistryLoginCmd(m.service, request), m.ensureAnimation())
}

// ---------------- removals ----------------

func (m *sandboxTUIModel) removeSelectedImage() (tea.Model, tea.Cmd) {
	row := m.selectedImage()
	if row == nil {
		m.closeDialog()
		return m, nil
	}
	copyRow := *row
	m.closeDialog()
	m.busyAction = "image remove"
	m.busyName = copyRow.Ref
	return m, tea.Batch(removeImageCmd(m.service, copyRow), m.ensureAnimation())
}

func (m *sandboxTUIModel) pruneImages() (tea.Model, tea.Cmd) {
	m.closeDialog()
	m.busyAction = "image prune"
	m.busyName = ""
	return m, tea.Batch(pruneImagesCmd(m.service), m.ensureAnimation())
}

func (m *sandboxTUIModel) logoutSelectedRegistry() (tea.Model, tea.Cmd) {
	row := m.selectedRegistry()
	if row == nil {
		m.closeDialog()
		return m, nil
	}
	copyRow := *row
	m.closeDialog()
	m.busyAction = "registry logout"
	m.busyName = copyRow.Registry
	return m, tea.Batch(removeRegistryLoginCmd(m.service, copyRow), m.ensureAnimation())
}

// ---------------- mouse ----------------

func (m *sandboxTUIModel) updateImagePullDialogMouse(mouse tea.Mouse, bounds tuiRect) (tea.Model, tea.Cmd) {
	if m.dialogButtonHit(mouse, bounds, "Pull") {
		m.pullFocus = tuiImagePullSubmitFocus
		return m.submitImagePull()
	}
	focus, ok := m.dialogFormControlAt(mouse, bounds, []tuiFormControl{
		{label: "Image reference", focus: 0}, {label: "Architecture", focus: 1},
	})
	if !ok {
		return m, nil
	}
	if focus == 1 {
		m.pullFocus = focus
		m.cycleImagePullArch(1)
		return m, nil
	}
	return m, m.focusImagePull(focus)
}

func (m *sandboxTUIModel) updateRegistryLoginDialogMouse(mouse tea.Mouse, bounds tuiRect) (tea.Model, tea.Cmd) {
	if m.dialogButtonHit(mouse, bounds, "Store login") {
		m.loginFocus = tuiRegistryLoginSubmitFocus
		return m.submitRegistryLogin()
	}
	focus, ok := m.dialogFormControlAt(mouse, bounds, []tuiFormControl{
		{label: "Registry", focus: 0}, {label: "Username", focus: 1}, {label: "Password / token", focus: 2},
	})
	if !ok {
		return m, nil
	}
	return m, m.focusRegistryLogin(focus)
}

// ---------------- dialog renderers ----------------

func (m sandboxTUIModel) renderImagePullDialog(theme tuiTheme, width int) string {
	header := m.dialogHeader(theme, "Pull Image", width)
	description := lipgloss.NewStyle().Foreground(theme.secondary).Render(
		"Pull an OCI image reference into the local store. Cached images boot without a network.")
	refLabel := formLabel(theme, "Image reference", m.pullFocus == 0)
	refField := renderInputField(theme, m.pullRef.View(), width, m.pullFocus == 0)
	archLabel := formLabel(theme, "Architecture", m.pullFocus == 1)
	archHint := "  (space cycles auto/amd64/arm64)"
	if m.pullArch == "auto" {
		archHint = "  (host architecture)"
	}
	arch := archLabel + "  " + lipgloss.NewStyle().Foreground(theme.text).Render(m.pullArch) +
		lipgloss.NewStyle().Foreground(theme.muted).Render(archHint)
	errorLine := ""
	if m.formError != "" {
		errorLine = lipgloss.NewStyle().Foreground(theme.error).Render(truncateText(m.formError, width))
	}
	button := renderDialogButton(theme, "Pull", m.pullFocus == tuiImagePullSubmitFocus, false)
	buttons := alignRight(button, width)
	hint := lipgloss.NewStyle().Foreground(theme.muted).Render("tab next  •  enter continue  •  esc cancel")
	gap := m.formSectionGap()
	fields := []string{refLabel + "\n" + refField, arch}
	return header + "\n" + description + gap + strings.Join(fields, gap) + "\n" + renderFormFooter(errorLine, buttons, hint)
}

func (m sandboxTUIModel) renderRegistryLoginDialog(theme tuiTheme, width int) string {
	header := m.dialogHeader(theme, "Registry Login", width)
	description := lipgloss.NewStyle().Foreground(theme.secondary).Render(
		"Store a credential for registry pulls. A docker-credential-* helper is used when configured.")
	registryLabel := formLabel(theme, "Registry", m.loginFocus == 0)
	registryField := renderInputField(theme, m.loginRegistry.View(), width, m.loginFocus == 0)
	usernameLabel := formLabel(theme, "Username", m.loginFocus == 1)
	usernameField := renderInputField(theme, m.loginUsername.View(), width, m.loginFocus == 1)
	passwordLabel := formLabel(theme, "Password / token", m.loginFocus == 2) +
		lipgloss.NewStyle().Foreground(theme.muted).Render("  write-only")
	passwordField := renderInputField(theme, m.loginPassword.View(), width, m.loginFocus == 2)
	note := lipgloss.NewStyle().Foreground(theme.warning).Render(
		"Without a helper the credential is base64-encoded in ~/.gantry/credentials.json (0600) — encoding, not encryption.")
	errorLine := ""
	if m.formError != "" {
		errorLine = lipgloss.NewStyle().Foreground(theme.error).Render(truncateText(m.formError, width))
	}
	button := renderDialogButton(theme, "Store login", m.loginFocus == tuiRegistryLoginSubmitFocus, false)
	buttons := alignRight(button, width)
	hint := lipgloss.NewStyle().Foreground(theme.muted).Render("tab next  •  ctrl+enter store  •  esc cancel")
	gap := m.formSectionGap()
	fields := []string{registryLabel + "\n" + registryField, usernameLabel + "\n" + usernameField, passwordLabel + "\n" + passwordField, note}
	return header + "\n" + description + gap + strings.Join(fields, gap) + "\n" + renderFormFooter(errorLine, buttons, hint)
}

func (m sandboxTUIModel) renderImageRemoveDialog(theme tuiTheme, width int) string {
	header := m.dialogHeader(theme, "Remove Image", width)
	row := m.selectedImage()
	if row == nil {
		return header + "\n\n" + lipgloss.NewStyle().Foreground(theme.muted).Render("No image selected.")
	}
	value := lipgloss.NewStyle().Bold(true).Foreground(theme.text).Render(row.Ref)
	detail := lipgloss.NewStyle().Foreground(theme.secondary).Render(defaultText(row.Arch, "?") + "  •  " +
		formatBytes(uint64(maxInt(0, int(row.Size)))) + "  •  " + shortImageDigest(row.Digest))
	warning := lipgloss.NewStyle().Foreground(theme.warning).Render("Sandboxes referencing this digest fall back to a re-pull.")
	if row.InUse {
		warning = lipgloss.NewStyle().Foreground(theme.error).Render("A sandbox currently references this image; starting it re-pulls from the registry.")
	}
	question := lipgloss.NewStyle().Bold(true).Foreground(theme.text).Render("Remove this cached image?")
	cancel := renderDialogButton(theme, "Cancel", !m.confirmRemove, false)
	remove := renderDialogButton(theme, "Remove", m.confirmRemove, true)
	buttons := alignRight(cancel+"  "+remove, width)
	hint := lipgloss.NewStyle().Foreground(theme.muted).Render("←/→ choose  •  enter confirm")
	return header + "\n\n" + value + "\n" + detail + "\n\n" + warning + "\n\n" + question + "\n\n" + renderConfirmationFooter(buttons, hint)
}

func (m sandboxTUIModel) renderImagePruneDialog(theme tuiTheme, width int) string {
	header := m.dialogHeader(theme, "Prune Images", width)
	count := m.prunableImageCount()
	var bytesTotal int64
	for _, row := range m.images {
		if !row.InUse {
			bytesTotal += row.Size
		}
	}
	value := lipgloss.NewStyle().Bold(true).Foreground(theme.text).Render(
		fmt.Sprintf("%d unused images  •  %s", count, formatBytes(uint64(maxInt(0, int(bytesTotal))))))
	warning := lipgloss.NewStyle().Foreground(theme.secondary).Render("Images referenced by a sandbox are kept.")
	question := lipgloss.NewStyle().Bold(true).Foreground(theme.text).Render("Remove every unreferenced image?")
	cancel := renderDialogButton(theme, "Cancel", !m.confirmRemove, false)
	prune := renderDialogButton(theme, "Prune", m.confirmRemove, true)
	buttons := alignRight(cancel+"  "+prune, width)
	hint := lipgloss.NewStyle().Foreground(theme.muted).Render("←/→ choose  •  enter confirm")
	return header + "\n\n" + value + "\n\n" + warning + "\n\n" + question + "\n\n" + renderConfirmationFooter(buttons, hint)
}

func (m sandboxTUIModel) renderRegistryLogoutDialog(theme tuiTheme, width int) string {
	header := m.dialogHeader(theme, "Registry Logout", width)
	row := m.selectedRegistry()
	if row == nil {
		return header + "\n\n" + lipgloss.NewStyle().Foreground(theme.muted).Render("No registry selected.")
	}
	value := lipgloss.NewStyle().Bold(true).Foreground(theme.text).Render(row.Registry)
	detail := lipgloss.NewStyle().Foreground(theme.secondary).Render(defaultText(row.Username, "") + "  •  " + defaultText(row.Source, ""))
	warning := lipgloss.NewStyle().Foreground(theme.warning).Render("Future pulls from this registry authenticate anonymously.")
	question := lipgloss.NewStyle().Bold(true).Foreground(theme.text).Render("Erase the stored credential?")
	cancel := renderDialogButton(theme, "Cancel", !m.confirmRemove, false)
	logout := renderDialogButton(theme, "Logout", m.confirmRemove, true)
	buttons := alignRight(cancel+"  "+logout, width)
	hint := lipgloss.NewStyle().Foreground(theme.muted).Render("←/→ choose  •  enter confirm")
	return header + "\n\n" + value + "\n" + detail + "\n\n" + warning + "\n\n" + question + "\n\n" + renderConfirmationFooter(buttons, hint)
}
