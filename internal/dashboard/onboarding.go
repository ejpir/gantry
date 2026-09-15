package dashboard

import (
	"context"
	"fmt"
	"strings"
	"time"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/ejpir/gantry/internal/orgauth"
	"github.com/ejpir/gantry/internal/remote"
)

// remoteOnboarding owns the location/login/profile steps, never manager
// credentials after submission. The create form retains its explicit target
// independently of environment defaults or the currently visible table row.
type remoteOnboarding struct {
	availableRemotes  []orgauth.AvailableRemote
	remoteGenerations map[string]uint64
	remoteConfigError string
	onboardInputs     []textinput.Model
	onboardFocus      int
	onboardCreating   bool
	onboardSuggestion *orgauth.AvailableRemote
	onboardChoices    []orgauth.AvailableRemote
	onboardProfiles   []remote.Profile
	onboardCA         string
	onboardGeneration uint64
	onboardCancel     context.CancelFunc
	onboardBusy       bool
	onboardURL        string
	onboardStatus     string
	onboardRemove     string
	lastOrgConfig     string
}

type onboardResultMsg struct {
	generation uint64
	kind       string
	name       string
	available  []orgauth.AvailableRemote
	session    *orgauth.Session
	err        error
}
type onboardURLMsg struct {
	generation    uint64
	url           string
	browserFailed bool
}
type onboardStreamMsg struct {
	event  tea.Msg
	stream <-chan tea.Msg
}

var loginOrganization = orgauth.Login
var openOrganizationBrowser = orgauth.OpenBrowser

func waitOnboardStream(stream <-chan tea.Msg) tea.Cmd {
	return func() tea.Msg {
		if event, ok := <-stream; ok {
			return onboardStreamMsg{event, stream}
		}
		return nil
	}
}

func (m *sandboxTUIModel) resetOnboarding() {
	if m.onboardCancel != nil {
		m.onboardCancel()
		m.onboardCancel = nil
	}
	m.onboardGeneration++
	for i := range m.onboardInputs {
		m.onboardInputs[i].Reset()
		m.onboardInputs[i].Blur()
	}
	m.onboardInputs = nil
	m.onboardBusy, m.onboardURL, m.onboardStatus = false, "", ""
	m.onboardSuggestion, m.onboardChoices, m.onboardProfiles = nil, nil, nil
	m.onboardCA, m.onboardRemove = "", ""
}

func (m *sandboxTUIModel) onboardingDialog(kind tuiDialog) {
	m.resetOnboarding()
	m.dialog, m.dialogScroll, m.formError, m.onboardFocus = kind, 0, "", 0
}

func (m *sandboxTUIModel) openCreateWizard() tea.Cmd {
	m.onboardCreating = true
	m.onboardingDialog(tuiCreateLocationDialog)
	return nil
}

func (m *sandboxTUIModel) openRemoteProfiles() tea.Cmd {
	m.onboardCreating = true
	m.onboardingDialog(tuiRemoteProfilesDialog)
	profiles, err := remote.List()
	if err != nil {
		m.formError = safeUIBlock(err.Error())
		return nil
	}
	m.onboardProfiles = profiles
	return nil
}

func (m *sandboxTUIModel) selectRemoteProfile(index int) tea.Cmd {
	if index == len(m.onboardProfiles) {
		return m.openRemoteAdd(nil, true)
	}
	if index < 0 || index >= len(m.onboardProfiles) {
		return nil
	}
	return m.openCreateForm(m.onboardProfiles[index].Name, "")
}

func (m *sandboxTUIModel) openOrganizationLogin(creating bool) tea.Cmd {
	m.onboardCreating = creating
	m.onboardingDialog(tuiOrganizationLoginDialog)
	m.setOnboardInputs([]string{"Organization config file", "Policy profile (optional)"}, []string{m.lastOrgConfig, ""})
	return m.focusOnboarding(0)
}

func (m *sandboxTUIModel) setOnboardInputs(labels, values []string) {
	m.onboardInputs = make([]textinput.Model, len(labels))
	for i, label := range labels {
		input := textinput.New()
		input.Prompt = ""
		input.Placeholder = label
		input.CharLimit = 4096
		if i < len(values) {
			input.SetValue(values[i])
		}
		if m.dialog == tuiRemoteAddDialog && i == 2 {
			input.CharLimit = 256
			input.EchoMode = textinput.EchoPassword
			input.EchoCharacter = '•'
		}
		m.onboardInputs[i] = input
	}
	m.applyInputTheme()
	m.resizeInputs()
}

func (m *sandboxTUIModel) focusOnboarding(index int) tea.Cmd {
	m.onboardFocus = clampInt(index, 0, len(m.onboardInputs))
	for i := range m.onboardInputs {
		m.onboardInputs[i].Blur()
	}
	m.ensureDialogFocusVisible()
	if m.onboardFocus < len(m.onboardInputs) {
		return m.onboardInputs[m.onboardFocus].Focus()
	}
	return nil
}

func (m *sandboxTUIModel) updateOnboardInput(msg tea.Msg) tea.Cmd {
	if m.onboardBusy || m.onboardFocus >= len(m.onboardInputs) {
		return nil
	}
	var cmd tea.Cmd
	m.onboardInputs[m.onboardFocus], cmd = m.onboardInputs[m.onboardFocus].Update(msg)
	return cmd
}

func (m *sandboxTUIModel) openOrganizationRemotes() tea.Cmd {
	m.onboardCreating = true
	m.onboardingDialog(tuiOrganizationRemotesDialog)
	m.onboardBusy = true
	generation, group := m.onboardGeneration, m.operations
	return func() tea.Msg {
		result := onboardResultMsg{generation: generation, kind: "choices"}
		if !group.begin() {
			result.err = context.Canceled
			return result
		}
		defer group.end()
		result.available, result.err = orgauth.AvailableRemotes(orgauth.SessionDir())
		return result
	}
}

func (m *sandboxTUIModel) submitOrganizationLogin() tea.Cmd {
	path := strings.TrimSpace(m.onboardInputs[0].Value())
	profile := strings.TrimSpace(m.onboardInputs[1].Value())
	if path == "" {
		m.formError = "Choose your organization's trusted configuration file."
		return m.focusOnboarding(0)
	}
	m.lastOrgConfig, m.onboardBusy, m.formError = path, true, ""
	ctx, cancel := context.WithTimeout(m.operations.ctx, 5*time.Minute)
	m.onboardCancel = cancel
	generation, group := m.onboardGeneration, m.operations
	stream := make(chan tea.Msg, 2)
	return func() tea.Msg {
		if !group.begin() {
			cancel()
			return onboardResultMsg{generation: generation, kind: "login", err: context.Canceled}
		}
		go func() {
			defer group.end()
			defer cancel()
			defer close(stream)
			result := onboardResultMsg{generation: generation, kind: "login"}
			trusted, err := orgauth.LoadConfig(path)
			if err == nil {
				result.session, err = loginOrganization(ctx, trusted, profile, func(url string) error {
					failed := openOrganizationBrowser(url) != nil
					select {
					case stream <- onboardURLMsg{generation: generation, url: url, browserFailed: failed}:
						return nil
					case <-ctx.Done():
						return ctx.Err()
					}
				})
			}
			if err == nil {
				err = ctx.Err()
			}
			if err == nil {
				err = orgauth.SaveSession(orgauth.SessionDir(), result.session)
			}
			result.err = err
			// The result holds a public receipt, not ID/access/refresh tokens.
			stream <- result // two slots: one URL and one final result, even on timeout
		}()
		return waitOnboardStream(stream)()
	}
}

func (m *sandboxTUIModel) handleOnboardResult(result onboardResultMsg) tea.Cmd {
	if result.generation != m.onboardGeneration {
		return nil
	}
	m.onboardBusy, m.onboardURL = false, ""
	if m.onboardCancel != nil {
		m.onboardCancel()
		m.onboardCancel = nil
	}
	if result.err != nil {
		m.formError = safeUIBlock(result.err.Error())
		return nil
	}
	switch result.kind {
	case "choices":
		m.availableRemotes, m.onboardChoices = result.available, result.available
		if len(result.available) == 0 {
			return m.openOrganizationLogin(true)
		}
	case "login":
		session := result.session
		m.availableRemotes = nil // replace stale suggestions for this view immediately
		if session.Catalog != nil && time.Now().Before(session.Catalog.ExpiresAt) {
			for _, p := range session.Catalog.Remotes {
				m.availableRemotes = append(m.availableRemotes, orgauth.AvailableRemote{Organization: session.Organization, ExpiresAt: session.Catalog.ExpiresAt, Profile: p})
			}
		}
		if session.Catalog == nil {
			m.formError = "Signed in as " + session.Organization + ", but no remote catalog is available. " + defaultText(session.CatalogError, "Configure remote_catalog in your trusted organization file, then sign in again.")
			return nil
		}
		if m.onboardCreating {
			m.onboardingDialog(tuiOrganizationRemotesDialog)
			m.onboardChoices = append([]orgauth.AvailableRemote(nil), m.availableRemotes...)
			m.onboardStatus = "Signed in to " + session.Organization + " · profile " + session.Profile
			if len(m.onboardChoices) == 0 {
				m.formError = "No remotes are currently available to this account. Sign in again to refresh."
			}
			return nil
		}
		m.closeDialog()
		m.setPage(tuiRemotesPage)
		return m.showToast(tuiToastSuccess, "Organization signed in", session.Organization+" · manager credentials remain separate")
	case "add":
		creating, suggestion := m.onboardCreating, m.onboardSuggestion
		m.closeDialog()
		if creating {
			organization := ""
			if suggestion != nil {
				organization = suggestion.Organization
			}
			return m.openCreateForm(result.name, organization)
		}
		return m.showToast(tuiToastSuccess, "Remote added", result.name)
	case "test", "remove":
		m.closeDialog()
		return m.showToast(tuiToastSuccess, "Remote "+result.kind+" succeeded", result.name)
	}
	return nil
}

func (m *sandboxTUIModel) selectOrganizationRemote(index int) tea.Cmd {
	if index < 0 || index >= len(m.onboardChoices) {
		return nil
	}
	suggestion := m.onboardChoices[index]
	if !time.Now().Before(suggestion.ExpiresAt) {
		m.formError = "Remote catalog expired; sign in again to refresh."
		return nil
	}
	profiles, err := remote.List()
	if err != nil {
		m.formError = safeUIBlock(err.Error())
		return nil
	}
	// Name collisions cannot redirect organization creation to an unrelated
	// existing profile. Renamed registrations match all connection metadata.
	for _, profile := range profiles {
		if sameRemoteEndpoint(profile, suggestion.Profile) {
			if _, err := remote.LoadToken(profile.Name); err == nil {
				return m.openCreateForm(profile.Name, suggestion.Organization)
			}
		}
	}
	return m.openRemoteAdd(&suggestion, true)
}

func sameRemoteEndpoint(a, b remote.Profile) bool {
	a.Name, b.Name = "", ""
	return a == b
}

func (m *sandboxTUIModel) openRemoteAdd(suggestion *orgauth.AvailableRemote, creating bool) tea.Cmd {
	m.onboardingDialog(tuiRemoteAddDialog)
	m.onboardCreating, m.onboardSuggestion = creating, suggestion
	values := []string{"", "", "", "", ""}
	if suggestion != nil {
		p := suggestion.Profile
		values[0], values[1], values[4], m.onboardCA = p.Name, p.URL, p.Fingerprint, p.CACert
	}
	m.setOnboardInputs(remoteAddLabels, values)
	if suggestion != nil {
		return m.focusOnboarding(2)
	}
	return m.focusOnboarding(0)
}

var remoteAddLabels = []string{"Remote name", "HTTPS URL", "Manager token", "CA file (optional)", "TLS fingerprint (optional)"}

func (m *sandboxTUIModel) submitRemoteAdd() tea.Cmd {
	profile := remote.Profile{Name: strings.TrimSpace(m.onboardInputs[0].Value()), URL: strings.TrimSpace(m.onboardInputs[1].Value()), CACert: m.onboardCA, Fingerprint: strings.TrimSpace(m.onboardInputs[4].Value())}
	caPath := strings.TrimSpace(m.onboardInputs[3].Value())
	token := m.onboardInputs[2].Value()
	m.onboardInputs[2].Reset() // write-only, including on failure/cancellation
	m.onboardBusy, m.formError = true, ""
	ctx, cancel := context.WithTimeout(m.operations.ctx, 15*time.Second)
	m.onboardCancel = cancel
	generation, group, suggestion := m.onboardGeneration, m.operations, m.onboardSuggestion
	return func() tea.Msg {
		defer cancel()
		defer func() { token = "" }()
		result := onboardResultMsg{generation: generation, kind: "add", name: profile.Name}
		if !group.begin() {
			result.err = context.Canceled
			return result
		}
		defer group.end()
		if caPath != "" {
			profile.CACert, result.err = remote.ReadCA(caPath)
		}
		if result.err == nil && suggestion != nil && !sameRemoteEndpoint(profile, suggestion.Profile) {
			result.err = fmt.Errorf("organization endpoint/trust must match the catalog; only the local remote name may change")
		}
		if result.err == nil {
			_, result.err = remote.Register(ctx, profile, token)
		}
		return result
	}
}

func (m *sandboxTUIModel) updateOnboardingKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	key := msg.String()
	if key == "esc" {
		m.closeDialog()
		return m, nil
	}
	if m.onboardBusy {
		return m, nil
	}
	switch m.dialog {
	case tuiCreateLocationDialog:
		switch key {
		case "down", "right", "tab":
			m.onboardFocus = (m.onboardFocus + 1) % 3
		case "up", "left", "shift+tab":
			m.onboardFocus = (m.onboardFocus + 2) % 3
		case "l":
			return m, m.openCreateForm("", "")
		case "r":
			return m, m.openRemoteProfiles()
		case "o":
			return m, m.openOrganizationRemotes()
		case "enter":
			if m.onboardFocus == 0 {
				return m, m.openCreateForm("", "")
			}
			if m.onboardFocus == 1 {
				return m, m.openRemoteProfiles()
			}
			return m, m.openOrganizationRemotes()
		}
	case tuiRemoteProfilesDialog:
		switch key {
		case "a":
			return m, m.openRemoteAdd(nil, true)
		case "up", "k", "shift+tab":
			m.onboardFocus = max(0, m.onboardFocus-1)
		case "down", "j", "tab":
			m.onboardFocus = min(len(m.onboardProfiles), m.onboardFocus+1)
		case "enter":
			return m, m.selectRemoteProfile(m.onboardFocus)
		}
		m.ensureDialogFocusVisible()
	case tuiOrganizationRemotesDialog:
		switch key {
		case "L", "r":
			return m, m.openOrganizationLogin(true)
		case "up", "k", "shift+tab":
			m.onboardFocus = max(0, m.onboardFocus-1)
		case "down", "j", "tab":
			m.onboardFocus = min(max(0, len(m.onboardChoices)-1), m.onboardFocus+1)
		case "enter":
			return m, m.selectOrganizationRemote(m.onboardFocus)
		}
		m.ensureDialogFocusVisible()
	case tuiRemoteRemoveDialog:
		return m.updateConfirmationDialogKey(key)
	default:
		switch key {
		case "tab", "down":
			return m, m.focusOnboarding((m.onboardFocus + 1) % (len(m.onboardInputs) + 1))
		case "shift+tab", "up":
			return m, m.focusOnboarding((m.onboardFocus + len(m.onboardInputs)) % (len(m.onboardInputs) + 1))
		case "enter", "ctrl+enter":
			if key == "enter" && m.onboardFocus < len(m.onboardInputs) {
				return m, m.focusOnboarding(m.onboardFocus + 1)
			}
			if m.dialog == tuiOrganizationLoginDialog {
				return m, m.submitOrganizationLogin()
			}
			return m, m.submitRemoteAdd()
		}
		return m, m.updateOnboardInput(msg)
	}
	return m, nil
}

func (m sandboxTUIModel) onboardLabels() (title, description, button string, labels []string) {
	if m.dialog == tuiRemoteAddDialog {
		description = "Probe TLS and authentication before saving. Manager token is write-only and stored separately (0600), never in the profile."
		if m.onboardSuggestion != nil {
			description = "Available from " + m.onboardSuggestion.Organization + ". " + description + " If the name already exists, choose another local name."
		}
		return "Add remote manager", description, "Test and add", remoteAddLabels
	}
	return "Organization sign-in", "Use the trusted organization.json supplied by your administrator. Sign-in opens your browser (code + PKCE); Gantry saves a token-free receipt and public remote catalog only.", "Sign in", []string{"Organization config file", "Policy profile (optional)"}
}

func (m sandboxTUIModel) renderOnboardingDialog(theme tuiTheme, width int) string {
	muted := lipgloss.NewStyle().Foreground(theme.secondary)
	errorLine := ""
	if m.formError != "" {
		errorLine = "\n" + lipgloss.NewStyle().Foreground(theme.error).Render(safeUIBlock(m.formError))
	}
	choice := func(label string, index int) string {
		return renderDialogButton(theme, label, m.onboardFocus == index, false)
	}
	switch m.dialog {
	case tuiCreateLocationDialog:
		return m.dialogHeader(theme, "Create sandbox · Location", width) + "\n\n" + muted.Render("Where should this sandbox run?") + "\n\n" + choice("Local", 0) + "\n" + muted.Render("On this computer. No organization sign-in required.") + "\n\n" + choice("Remote", 1) + "\n" + muted.Render("Add or select a standalone manager. No organization required.") + "\n\n" + choice("Organization", 2) + "\n" + muted.Render("Sign in, discover available remotes, then choose a manager.") + "\n\n" + muted.Render("↑/↓ choose · enter continue · esc cancel")
	case tuiRemoteProfilesDialog:
		body := m.dialogHeader(theme, "Create sandbox · Remote", width) + "\n\n" + muted.Render("Standalone remotes use their own manager token; organization login is not required.")
		for i, profile := range m.onboardProfiles {
			body += "\n\n" + choice(safeUILine(profile.Name), i) + "\n" + muted.Render(safeUILine(profile.URL))
		}
		return body + "\n\n" + choice("Add remote", len(m.onboardProfiles)) + errorLine + "\n\n" + muted.Render("↑/↓ choose · enter continue · a add · esc cancel")
	case tuiOrganizationRemotesDialog:
		body := m.dialogHeader(theme, "Create sandbox · Organization remote", width) + "\n\n" + muted.Render(defaultText(m.onboardStatus, "Choose an available remote. Discovery does not grant manager access.")) + "\n"
		if m.onboardBusy {
			body += "\nLoading signed-in organizations…"
		}
		for i, suggestion := range m.onboardChoices {
			body += "\n" + choice(safeUILine(suggestion.Organization+" / "+suggestion.Profile.Name), i) + "\n" + muted.Render(safeUILine(suggestion.Profile.URL))
		}
		return body + errorLine + "\n\n" + muted.Render("↑/↓ choose · enter continue · L sign in / refresh · esc cancel")
	case tuiRemoteRemoveDialog:
		return m.dialogHeader(theme, "Remove remote profile", width) + "\n\n" + safeUILine(m.onboardRemove) + "\n\n" + muted.Render("Remove this local profile and its token? This does NOT delete any remote sandbox or revoke the manager token.") + "\n\n" + alignRight(renderDialogButton(theme, "Cancel", !m.confirmRemove, false)+"  "+renderDialogButton(theme, "Remove", m.confirmRemove, true), width) + errorLine + "\n\n" + muted.Render("←/→ choose · enter confirm")
	}
	title, description, button, labels := m.onboardLabels()
	body := m.dialogHeader(theme, title, width) + "\n" + muted.Render(safeUIBlock(description))
	for i, input := range m.onboardInputs {
		body += m.formSectionGap() + formLabel(theme, labels[i], m.onboardFocus == i) + "\n" + renderInputField(theme, input.View(), width, m.onboardFocus == i)
	}
	if m.onboardBusy {
		body += "\n\n" + muted.Render(defaultText(m.onboardStatus, "Working… esc cancels."))
		if m.onboardURL != "" {
			body += "\n\n" + safeUIBlock(m.onboardURL) + "\n" + muted.Render("Open this URL in your browser. ctrl+c copies the authorization URL.")
		}
	} else {
		body += "\n\n" + alignRight(renderDialogButton(theme, button, m.onboardFocus == len(labels), false), width)
	}
	return body + errorLine + "\n\n" + muted.Render("tab next · ctrl+enter submit · esc cancel")
}

func (m *sandboxTUIModel) updateOnboardingMouse(mouse tea.Mouse, bounds tuiRect) (tea.Model, tea.Cmd) {
	if m.onboardBusy {
		return m, nil
	}
	if m.dialog == tuiRemoteRemoveDialog {
		return m.updateConfirmationDialogMouse(mouse, bounds)
	}
	var controls []tuiFormControl
	switch m.dialog {
	case tuiCreateLocationDialog:
		controls = []tuiFormControl{{"Local", 0}, {"Remote", 1}, {"Organization", 2}}
	case tuiRemoteProfilesDialog:
		for i, profile := range m.onboardProfiles {
			controls = append(controls, tuiFormControl{profile.Name, i})
		}
		controls = append(controls, tuiFormControl{"Add remote", len(m.onboardProfiles)})
	case tuiOrganizationRemotesDialog:
		for i, suggestion := range m.onboardChoices {
			controls = append(controls, tuiFormControl{suggestion.Organization + " / " + suggestion.Profile.Name, i})
		}
	default:
		_, _, button, labels := m.onboardLabels()
		for i, label := range labels {
			controls = append(controls, tuiFormControl{label, i})
		}
		controls = append(controls, tuiFormControl{button, len(labels)})
	}
	focus, ok := m.dialogFormControlAt(mouse, bounds, controls)
	if !ok {
		return m, nil
	}
	switch m.dialog {
	case tuiCreateLocationDialog:
		if focus == 0 {
			return m, m.openCreateForm("", "")
		}
		if focus == 1 {
			return m, m.openRemoteProfiles()
		}
		return m, m.openOrganizationRemotes()
	case tuiRemoteProfilesDialog:
		return m, m.selectRemoteProfile(focus)
	case tuiOrganizationRemotesDialog:
		return m, m.selectOrganizationRemote(focus)
	default:
		cmd := m.focusOnboarding(focus)
		if focus == len(m.onboardInputs) {
			if m.dialog == tuiOrganizationLoginDialog {
				return m, m.submitOrganizationLogin()
			}
			return m, m.submitRemoteAdd()
		}
		return m, cmd
	}
}
