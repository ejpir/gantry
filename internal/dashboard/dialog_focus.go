package dashboard

import (
	"strings"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
)

type dialogFocusViewport struct {
	width     int
	height    int
	maxScroll int
	content   string
}

// ensureDialogFocusVisible follows keyboard focus through forms whose content
// is taller than the terminal. Manual wheel scrolling remains undisturbed
// until focus changes again.
func (m *sandboxTUIModel) ensureDialogFocusVisible() {
	if m.dialog == tuiNoDialog {
		m.dialogScroll = 0
		return
	}
	viewport := m.dialogFocusViewport()
	m.dialogScroll = clampInt(m.dialogScroll, 0, viewport.maxScroll)
	switch m.dialog {
	case tuiSortDialog, tuiSandboxFilterDialog:
		m.ensureQueryDialogFocusVisible(viewport)
	case tuiCreateDialog:
		m.ensureCreateDialogFocusVisible(viewport)
	default:
		m.ensureLabeledDialogFocusVisible(viewport)
	}
}

func (m sandboxTUIModel) dialogFocusViewport() dialogFocusViewport {
	width, height, content, _ := m.dialogMeasured(tuiThemeFor(m.dark), m.dialog)
	viewportHeight := maxInt(1, height-4)
	return dialogFocusViewport{
		width: width, height: viewportHeight,
		maxScroll: maxInt(0, lipgloss.Height(content)-viewportHeight), content: content,
	}
}

func (m *sandboxTUIModel) ensureQueryDialogFocusVisible(viewport dialogFocusViewport) {
	row := 5 // filter input text, below title, label, and border
	if m.dialog == tuiSortDialog {
		_, options := m.sortDialogLayout(tuiThemeFor(m.dark), maxInt(10, viewport.width-6))
		row = options[clampInt(m.sortCursor, 0, len(options)-1)].row
	}
	if row < m.dialogScroll {
		m.dialogScroll = row
	}
	if row >= m.dialogScroll+viewport.height {
		m.dialogScroll = row - viewport.height + 1
	}
	m.dialogScroll = clampInt(m.dialogScroll, 0, viewport.maxScroll)
}

func (m *sandboxTUIModel) ensureCreateDialogFocusVisible(viewport dialogFocusViewport) {
	layout := m.createLayout(tuiThemeFor(m.dark), maxInt(10, viewport.width-6))
	target := layout.controls[m.createFocus]
	switch m.createFocus {
	case 10:
		m.dialogScroll = viewport.maxScroll
		return
	case 0:
		m.dialogScroll = 0
		return
	}
	if target.y < m.dialogScroll {
		m.dialogScroll = target.y
	}
	if target.y+target.h > m.dialogScroll+viewport.height {
		m.dialogScroll = clampInt(target.y+minInt(target.h, viewport.height)-viewport.height, 0, viewport.maxScroll)
	}
}

func (m *sandboxTUIModel) ensureLabeledDialogFocusVisible(viewport dialogFocusViewport) {
	needle, fromEnd := m.dialogFocusTarget()
	if needle == "" || viewport.maxScroll == 0 {
		return
	}
	if m.dialogFocusAtStart() {
		m.dialogScroll = 0
		return
	}
	line := dialogFocusLine(strings.Split(ansi.Strip(viewport.content), "\n"), needle, fromEnd)
	if line < 0 {
		return
	}
	if line < m.dialogScroll+1 {
		m.dialogScroll = maxInt(0, line-1)
	}
	// Keep the focused label plus its value/control and one context row in
	// view. Buttons resolve from the end and naturally clamp to maxScroll.
	if line+2 >= m.dialogScroll+viewport.height {
		m.dialogScroll = minInt(viewport.maxScroll, line+3-viewport.height)
	}
}

func dialogFocusLine(lines []string, needle string, fromEnd bool) int {
	if fromEnd {
		for index := len(lines) - 1; index >= 0; index-- {
			if strings.Contains(lines[index], needle) {
				return index
			}
		}
		return -1
	}
	for index := minInt(2, len(lines)); index < len(lines); index++ {
		if strings.Contains(lines[index], needle) {
			return index
		}
	}
	return -1
}

func (m sandboxTUIModel) dialogFocusAtStart() bool {
	switch m.dialog {
	case tuiCreateLocationDialog, tuiRemoteProfilesDialog, tuiOrganizationLoginDialog, tuiRemoteAddDialog, tuiOrganizationRemotesDialog:
		return m.onboardFocus == 0
	case tuiCreateDialog:
		return m.createFocus == 0
	case tuiEditDialog:
		return m.editFocus == 0
	case tuiShareAddDialog:
		return m.shareFocus == 0
	case tuiPortPublishDialog:
		return m.portFocus == 0
	case tuiNetworkPolicyDialog:
		return m.policyFocus == 0
	case tuiRuleAddDialog:
		return m.ruleFocus == 0
	case tuiSecretAddDialog:
		return m.secretFocus == 0
	case tuiMCPRemoteDialog:
		return m.mcpFocus == 0
	case tuiMCPFilesystemDialog:
		return m.mcpFSFocus == 0
	case tuiImagePullDialog:
		return m.pullFocus == 0
	case tuiRegistryLoginDialog:
		return m.loginFocus == 0
	default:
		return false
	}
}

func (m sandboxTUIModel) dialogFocusTarget() (needle string, fromEnd bool) {
	choose := func(index int, values []string) string {
		if index < 0 || index >= len(values) {
			return ""
		}
		return values[index]
	}
	switch m.dialog {
	case tuiCreateDialog:
		return choose(m.createFocus, []string{"Name", "OCI image", "Runtime", "Kernel", "SSH", "Dev Containers", "CPUs", "Memory", "Persistent disk", "Process isolation", "Create sandbox"}), m.createFocus == 10
	case tuiEditDialog:
		return choose(m.editFocus, []string{"SSH", "Dev Containers", "CPUs", "Memory", "Process isolation", "Save"}), m.editFocus == 5
	case tuiShareAddDialog:
		_, _, button := m.shareDialogCopy()
		return choose(m.shareFocus, []string{"Sandbox", "Tag", "Host path", "Mount point", "Guest owner", "Mode", button}), m.shareFocus == 6
	case tuiPortPublishDialog:
		return choose(m.portFocus, []string{"Sandbox", "Host bind", "Guest port", "Protocol", "Publish"}), m.portFocus == 4
	case tuiNetworkPolicyDialog:
		return choose(m.policyFocus, []string{"Sandbox", "Policy file", "Local network override", "Apply"}), m.policyFocus == 3
	case tuiRuleAddDialog:
		if m.ruleProtocol == "dns" {
			return choose(m.ruleFocus, []string{"Sandbox", "Decision", "Domain", "Protocol", "Destination ports", m.ruleAddButtonLabel()}), m.ruleFocus == 5
		}
		return choose(m.ruleFocus, []string{"Sandbox", "Decision", "Destination", "Protocol", "Destination ports", "Add rule"}), m.ruleFocus == 5
	case tuiSecretAddDialog:
		return choose(m.secretFocus, []string{"Sandbox", "Name", "Value", "Add secret"}), m.secretFocus == 3
	case tuiMCPRemoteDialog:
		button := "Add server"
		if m.mcpEditing {
			button = "Save server"
		}
		return choose(m.mcpFocus, []string{"Sandbox", "Name", "HTTPS URL", "Authentication", "Secret / provider reference", "Header name", "Allow tool globs", "Deny tool globs", "Additional redact secret names", button}), m.mcpFocus == mcpRemoteSubmitFocus
	case tuiMCPFilesystemDialog:
		return choose(m.mcpFSFocus, []string{"Sandbox", "Guest root", "Unprivileged guest user", "Save"}), m.mcpFSFocus == 3
	case tuiImagePullDialog:
		return choose(m.pullFocus, []string{"Image reference", "Architecture", "Pull"}), m.pullFocus == tuiImagePullSubmitFocus
	case tuiOrganizationLoginDialog, tuiRemoteAddDialog:
		_, _, button, labels := m.onboardLabels()
		return choose(m.onboardFocus, append(append([]string(nil), labels...), button)), m.onboardFocus == len(labels)
	case tuiCreateLocationDialog:
		return choose(m.onboardFocus, []string{"Local", "Remote", "Organization"}), false
	case tuiRemoteProfilesDialog:
		if m.onboardFocus < len(m.onboardProfiles) {
			return m.onboardProfiles[m.onboardFocus].Name, false
		}
		return "Add remote", true
	case tuiOrganizationRemotesDialog:
		if m.onboardFocus < len(m.onboardChoices) {
			choice := m.onboardChoices[m.onboardFocus]
			return choice.Organization + " / " + choice.Profile.Name, false
		}
		return "", false
	case tuiRegistryLoginDialog:
		return choose(m.loginFocus, []string{"Registry", "Username", "Password / token", "Store login"}), m.loginFocus == tuiRegistryLoginSubmitFocus
	default:
		return "", false
	}
}
