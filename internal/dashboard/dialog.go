package dashboard

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/atotto/clipboard"
	dashboardapi "github.com/ejpir/gantry/internal/dashboard/api"
	"github.com/ejpir/gantry/internal/secret"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
)

var writeDashboardClipboard = clipboard.WriteAll

func (m *sandboxTUIModel) updateDialogKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	if msg.String() == "ctrl+c" {
		return m, m.copyDialogCmd()
	}
	switch msg.String() {
	case "ctrl+up":
		m.scrollDialog(-1)
		return m, nil
	case "ctrl+down":
		m.scrollDialog(1)
		return m, nil
	case "ctrl+pgup":
		m.scrollDialog(-m.dialogViewportHeight())
		return m, nil
	case "ctrl+pgdown":
		m.scrollDialog(m.dialogViewportHeight())
		return m, nil
	}
	switch m.dialog {
	case tuiCreateDialog:
		return m.updateCreateDialogKey(msg)
	case tuiEditDialog:
		return m.updateEditDialogKey(msg)
	case tuiShareAddDialog:
		return m.updateShareDialogKey(msg)
	case tuiPortPublishDialog:
		return m.updatePortDialogKey(msg)
	case tuiNetworkPolicyDialog:
		return m.updateNetworkPolicyDialogKey(msg)
	case tuiRuleAddDialog:
		return m.updateRuleAddDialogKey(msg)
	case tuiSecretAddDialog:
		return m.updateSecretAddDialogKey(msg)
	case tuiRemoveDialog, tuiShareRemoveDialog, tuiPortUnpublishDialog, tuiRuleRemoveDialog, tuiSecretRemoveDialog, tuiUpdateDialog:
		return m.updateConfirmationDialogKey(msg.String())
	case tuiHelpDialog, tuiInfoDialog:
		switch msg.String() {
		case "c":
			return m, m.copyDialogCmd()
		case "esc", "q", "?", "enter", "i":
			m.closeDialog()
		case "up", "k":
			m.scrollDialog(-1)
		case "down", "j":
			m.scrollDialog(1)
		case "pgup":
			m.scrollDialog(-m.dialogViewportHeight())
		case "pgdown", "space", " ":
			m.scrollDialog(m.dialogViewportHeight())
		case "home", "g":
			m.dialogScroll = 0
		case "end", "G":
			m.dialogScroll = m.dialogMaxScroll()
		}
	}
	return m, nil
}

func (m *sandboxTUIModel) updateFocusedDialogInput(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch m.dialog {
	case tuiCreateDialog:
		switch m.createFocus {
		case 0:
			m.createName, cmd = m.createName.Update(msg)
		case 1:
			m.createImage, cmd = m.createImage.Update(msg)
		}
	case tuiShareAddDialog:
		switch m.shareFocus {
		case 1:
			m.shareTag, cmd = m.shareTag.Update(msg)
		case 2:
			m.sharePath, cmd = m.sharePath.Update(msg)
		case 3:
			m.shareMount, cmd = m.shareMount.Update(msg)
		case 4:
			m.shareOwner, cmd = m.shareOwner.Update(msg)
		}
	case tuiPortPublishDialog:
		switch m.portFocus {
		case 1:
			m.portBind, cmd = m.portBind.Update(msg)
		case 2:
			m.portGuest, cmd = m.portGuest.Update(msg)
		}
	case tuiNetworkPolicyDialog:
		if m.policyFocus == 1 {
			m.policyPath, cmd = m.policyPath.Update(msg)
		}
	case tuiRuleAddDialog:
		switch m.ruleFocus {
		case 2:
			m.ruleTarget, cmd = m.ruleTarget.Update(msg)
		case 4:
			m.rulePorts, cmd = m.rulePorts.Update(msg)
		}
	case tuiSecretAddDialog:
		switch m.secretFocus {
		case 1:
			m.secretName, cmd = m.secretName.Update(msg)
		case 2:
			m.secretValue, cmd = m.secretValue.Update(msg)
		}
	}
	return m, cmd
}

func (m sandboxTUIModel) copyDialogCmd() tea.Cmd {
	value, label := m.dialogCopyValue()
	return func() tea.Msg {
		return tuiClipboardMsg{label: label, err: writeDashboardClipboard(value)}
	}
}

func (m sandboxTUIModel) dialogCopyValue() (value, label string) {
	wholeDialog := func(label string) (string, string) {
		_, _, content, _ := m.dialogMeasured(tuiThemeFor(m.dark), m.dialog)
		return strings.TrimSpace(ansi.Strip(content)), label
	}
	switch m.dialog {
	case tuiCreateDialog:
		switch m.createFocus {
		case 0:
			return m.createName.Value(), "sandbox name"
		case 1:
			return m.createImage.Value(), "OCI image"
		case 2:
			return m.createRuntime, "runtime"
		case 3:
			return defaultText(m.createKernelSelection(), "auto"), "kernel"
		case 4:
			return strconv.Itoa(m.createCPUs.Value), "CPU count"
		case 5:
			return strconv.Itoa(m.createMemory.Value), "memory MiB"
		case 6:
			return strconv.Itoa(m.createDisk.Value), "disk MiB"
		case 7:
			return m.createIsolation, "process isolation"
		}
	case tuiEditDialog:
		switch m.editFocus {
		case 0:
			return strconv.Itoa(m.editCPUs.Value), "CPU count"
		case 1:
			return strconv.Itoa(m.editMemory.Value), "memory MiB"
		case 2:
			return m.editIsolation, "process isolation"
		}
	case tuiShareAddDialog:
		switch m.shareFocus {
		case 0:
			return m.shareSandbox.Value(), "sandbox"
		case 1:
			return m.shareTag.Value(), "share tag"
		case 2:
			return m.sharePath.Value(), "host path"
		case 3:
			return m.shareMount.Value(), "mount point"
		case 4:
			return m.shareOwner.Value(), "guest owner"
		case 5:
			if m.shareRO {
				return "read-only", "share mode"
			}
			return "read-write", "share mode"
		}
	case tuiPortPublishDialog:
		switch m.portFocus {
		case 0:
			return m.portSandbox.Value(), "sandbox"
		case 1:
			return m.portBind.Value(), "host bind"
		case 2:
			return m.portGuest.Value(), "guest port"
		case 3:
			if m.portUDP {
				return "udp", "protocol"
			}
			return "tcp", "protocol"
		}
	case tuiNetworkPolicyDialog:
		switch m.policyFocus {
		case 0:
			return m.policySandbox.Value(), "sandbox"
		case 1:
			return m.policyPath.Value(), "policy file"
		case 2:
			if m.policyLocal {
				return "allowed", "local network override"
			}
			return "blocked", "local network override"
		}
	case tuiRuleAddDialog:
		switch m.ruleFocus {
		case 0:
			return m.ruleSandbox.Value(), "sandbox"
		case 1:
			return m.ruleAction, "decision"
		case 2:
			if m.ruleProtocol == "dns" {
				return m.ruleTarget.Value(), "domain"
			}
			return m.ruleTarget.Value(), "destination"
		case 3:
			return m.ruleProtocol, "protocol"
		case 4:
			return m.rulePorts.Value(), "destination ports"
		}
	case tuiSecretAddDialog:
		switch m.secretFocus {
		case 0:
			return m.secretSandbox.Value(), "sandbox"
		case 1:
			return m.secretName.Value(), "secret name"
		case 2:
			return m.secretValue.Value(), "secret value"
		}
	case tuiInfoDialog:
		return wholeDialog("sandbox details")
	case tuiHelpDialog:
		return wholeDialog("keyboard help")
	}
	return wholeDialog("dialog fields")
}

func (m *sandboxTUIModel) updateConfirmationDialogKey(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "esc", "q", "n", "N":
		m.closeDialog()
	case "left", "h":
		m.confirmRemove = false
	case "right", "l", "tab", "shift+tab":
		m.confirmRemove = !m.confirmRemove
	case "y", "Y":
		m.confirmRemove = true
		return m.submitConfirmationDialog()
	case "enter":
		if m.confirmRemove {
			return m.submitConfirmationDialog()
		}
		m.closeDialog()
	}
	return m, nil
}

func (m *sandboxTUIModel) submitConfirmationDialog() (tea.Model, tea.Cmd) {
	switch m.dialog {
	case tuiRemoveDialog:
		return m.removeSelected()
	case tuiShareRemoveDialog:
		return m.removeSelectedShare()
	case tuiPortUnpublishDialog:
		return m.unpublishSelectedPort()
	case tuiRuleRemoveDialog:
		return m.removeSelectedRule()
	case tuiSecretRemoveDialog:
		return m.removeSelectedSecret()
	case tuiUpdateDialog:
		return m.beginUpdate()
	default:
		return m, nil
	}
}

func (m *sandboxTUIModel) beginUpdate() (tea.Model, tea.Cmd) {
	if !m.updateStatus.Available {
		m.closeDialog()
		return m, nil
	}
	latest := m.updateStatus.Latest
	return m.beginAction("update", latest, []string{"update", "--wait-pid", fmt.Sprint(os.Getpid())}, false)
}

func (m *sandboxTUIModel) updateCreateDialogKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.closeDialog()
		return m, nil
	case "tab", "down":
		return m, m.focusCreate((m.createFocus + 1) % 9)
	case "shift+tab", "up":
		return m, m.focusCreate((m.createFocus + 8) % 9)
	case "left", "h":
		if m.adjustCreateChoice(-1) {
			return m, nil
		}
	case "right", "l":
		if m.adjustCreateChoice(1) {
			return m, nil
		}
	case " ", "space":
		if m.createFocus == 2 || m.createFocus == 3 || m.createFocus == 7 {
			m.adjustCreateChoice(1)
			return m, nil
		}
	case "pgup":
		if m.adjustCreateSlider(8) {
			return m, nil
		}
	case "pgdown":
		if m.adjustCreateSlider(-8) {
			return m, nil
		}
	case "home":
		if m.setCreateSliderBoundary(false) {
			return m, nil
		}
	case "end":
		if m.setCreateSliderBoundary(true) {
			return m, nil
		}
	case "ctrl+enter":
		return m.submitCreate()
	case "enter":
		if m.createFocus < 8 {
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

func (m *sandboxTUIModel) adjustCreateChoice(delta int) bool {
	switch m.createFocus {
	case 2:
		if m.createRuntime == "runsc" {
			m.createRuntime = "crun"
		} else {
			m.createRuntime = "runsc"
		}
		return true
	case 3:
		m.cycleCreateKernel(delta)
		return true
	case 7:
		m.createIsolation = cycleIsolation(m.createIsolation, delta)
		return true
	default:
		return m.adjustCreateSlider(delta)
	}
}

func (m *sandboxTUIModel) adjustCreateSlider(delta int) bool {
	switch m.createFocus {
	case 4:
		m.createCPUs.Adjust(delta)
		return true
	case 5:
		m.createMemory.Adjust(delta)
		return true
	case 6:
		m.createDisk.Adjust(delta)
		return true
	default:
		return false
	}
}

func (m *sandboxTUIModel) setCreateSliderBoundary(maximum bool) bool {
	var slider *resourceSlider
	switch m.createFocus {
	case 4:
		slider = &m.createCPUs
	case 5:
		slider = &m.createMemory
	case 6:
		slider = &m.createDisk
	default:
		return false
	}
	if maximum {
		slider.Set(slider.Max)
	} else {
		slider.Set(slider.Min)
	}
	return true
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
	if m.createCPUs.Value != 1 {
		argv = append(argv, "-cpus", strconv.Itoa(m.createCPUs.Value))
	}
	if m.createMemory.Value != 512 {
		argv = append(argv, "-mem", strconv.Itoa(m.createMemory.Value))
	}
	if m.createDisk.Value != int(m.limits.DefaultDiskSizeMiB) {
		argv = append(argv, "-disk-size", strconv.Itoa(m.createDisk.Value))
	}
	if m.createIsolation != "auto" {
		argv = append(argv, "-process-isolation", m.createIsolation)
	}
	return argv
}

func (m *sandboxTUIModel) openCreateDialog() tea.Cmd {
	m.dialog = tuiCreateDialog
	m.dialogScroll = 0
	m.formError = ""
	m.createName.Reset()
	m.createImage.Reset()
	m.createCPUs = newResourceSlider(1, m.limits.MaxVCPUs, 1, 1)
	m.createMemory = newResourceSlider(int(m.limits.MinMemoryMB), int(m.limits.MaxMemoryMB), 128, 512)
	m.createDisk = newResourceSlider(int(m.limits.MinDiskSizeMiB), int(m.limits.MaxDiskSizeMiB), 512, int(m.limits.DefaultDiskSizeMiB))
	m.createRuntime = "crun"
	m.createKernels = m.service.KernelChoices()
	m.createKernel = 0
	m.createIsolation = "auto"
	m.resizeInputs()
	return m.focusCreate(0)
}

func (m *sandboxTUIModel) focusCreate(index int) tea.Cmd {
	m.createFocus = clampInt(index, 0, 8)
	m.createName.Blur()
	m.createImage.Blur()
	m.ensureDialogFocusVisible()
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
	if err := m.service.ValidateCreate(name, uint(m.createMemory.Value), uint(m.createDisk.Value), m.createCPUs.Value, m.createIsolation); err != nil {
		m.formError = err.Error()
		switch dashboardErrorField(err) {
		case "cpu":
			return m, m.focusCreate(4)
		case "memory":
			return m, m.focusCreate(5)
		case "disk":
			return m, m.focusCreate(6)
		case "isolation":
			return m, m.focusCreate(7)
		default:
			return m, m.focusCreate(0)
		}
	}
	return m.beginAction("create", name, m.createArgv(name), false)
}

func (m *sandboxTUIModel) openEditDialog() tea.Cmd {
	selected := m.selected()
	if selected == nil {
		return nil
	}
	if selected.ConfigError {
		return m.showToast(tuiToastError, "Cannot edit sandbox", "The saved sandbox configuration is unavailable.")
	}
	m.dialog = tuiEditDialog
	m.dialogScroll = 0
	m.formError = ""
	m.editCPUs = newResourceSlider(1, m.limits.MaxVCPUs, 1, maxInt(1, selected.VCPUs))
	m.editMemory = newResourceSlider(int(m.limits.MinMemoryMB), int(m.limits.MaxMemoryMB), 128, int(selected.MemMB))
	m.editIsolation = selected.ProcessIsolation
	if m.editIsolation == "" {
		m.editIsolation = "auto"
	}
	m.resizeInputs()
	return m.focusEdit(0)
}

func (m *sandboxTUIModel) updateEditDialogKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.closeDialog()
		return m, nil
	case "tab", "down":
		return m, m.focusEdit((m.editFocus + 1) % 4)
	case "shift+tab", "up":
		return m, m.focusEdit((m.editFocus + 3) % 4)
	case "left", "h":
		if m.adjustEditSlider(-1) {
			return m, nil
		}
		if m.editFocus == 2 {
			m.editIsolation = cycleIsolation(m.editIsolation, -1)
			return m, nil
		}
	case "right", "l":
		if m.adjustEditSlider(1) {
			return m, nil
		}
		if m.editFocus == 2 {
			m.editIsolation = cycleIsolation(m.editIsolation, 1)
			return m, nil
		}
	case " ", "space":
		if m.editFocus == 2 {
			m.editIsolation = cycleIsolation(m.editIsolation, 1)
			return m, nil
		}
	case "pgup":
		if m.adjustEditSlider(8) {
			return m, nil
		}
	case "pgdown":
		if m.adjustEditSlider(-8) {
			return m, nil
		}
	case "home":
		if m.setEditSliderBoundary(false) {
			return m, nil
		}
	case "end":
		if m.setEditSliderBoundary(true) {
			return m, nil
		}
	case "ctrl+enter":
		return m.submitEdit()
	case "enter":
		if m.editFocus < 3 {
			return m, m.focusEdit(m.editFocus + 1)
		}
		return m.submitEdit()
	}

	m.formError = ""
	return m, nil
}

func (m *sandboxTUIModel) adjustEditSlider(delta int) bool {
	switch m.editFocus {
	case 0:
		m.editCPUs.Adjust(delta)
		return true
	case 1:
		m.editMemory.Adjust(delta)
		return true
	default:
		return false
	}
}

// setEditSliderBoundary mirrors the create dialog's home/end jumps.
func (m *sandboxTUIModel) setEditSliderBoundary(maximum bool) bool {
	var slider *resourceSlider
	switch m.editFocus {
	case 0:
		slider = &m.editCPUs
	case 1:
		slider = &m.editMemory
	default:
		return false
	}
	if maximum {
		slider.Set(slider.Max)
	} else {
		slider.Set(slider.Min)
	}
	return true
}

func (m *sandboxTUIModel) focusEdit(index int) tea.Cmd {
	m.editFocus = clampInt(index, 0, 3)
	m.ensureDialogFocusVisible()
	return nil
}

func (m *sandboxTUIModel) submitEdit() (tea.Model, tea.Cmd) {
	selected := m.selected()
	if selected == nil {
		m.closeDialog()
		return m, nil
	}
	memMB, vcpus := uint(m.editMemory.Value), m.editCPUs.Value
	err := m.service.ValidateResources(memMB, vcpus, m.editIsolation)
	if err != nil {
		m.formError = err.Error()
		if strings.Contains(err.Error(), "CPU") {
			return m, m.focusEdit(0)
		}
		if strings.Contains(err.Error(), "isolation") {
			return m, m.focusEdit(2)
		}
		return m, m.focusEdit(1)
	}
	m.dialog = tuiNoDialog
	m.dialogScroll = 0
	m.busyAction = "edit"
	m.busyName = selected.Name
	return m, tea.Batch(saveSandboxResourcesCmd(m.service, selected.Name, memMB, vcpus, m.editIsolation, selected.State == tuiRunning), m.ensureAnimation())
}

func cycleIsolation(current string, delta int) string {
	choices := []string{"auto", "required", "off"}
	index := 0
	for i, choice := range choices {
		if choice == current {
			index = i
			break
		}
	}
	return choices[(index+delta+len(choices))%len(choices)]
}

type tuiFormKeyAction uint8

const (
	tuiFormKeyInput tuiFormKeyAction = iota
	tuiFormKeyClose
	tuiFormKeyFocus
	tuiFormKeyToggle
	tuiFormKeySubmit
)

func classifyFormKey(key string, focus, lastFocus, toggleFocus int) (tuiFormKeyAction, int) {
	switch key {
	case "esc":
		return tuiFormKeyClose, focus
	case "tab", "down":
		return tuiFormKeyFocus, (focus + 1) % (lastFocus + 1)
	case "shift+tab", "up":
		return tuiFormKeyFocus, (focus + lastFocus) % (lastFocus + 1)
	case "left", "right", " ", "space":
		if focus == toggleFocus {
			return tuiFormKeyToggle, focus
		}
	case "ctrl+enter":
		return tuiFormKeySubmit, focus
	case "enter":
		if focus == lastFocus {
			return tuiFormKeySubmit, focus
		}
		return tuiFormKeyFocus, focus + 1
	}
	return tuiFormKeyInput, focus
}

func (m *sandboxTUIModel) applyPickerFormKey(key string, focus, lastFocus, toggleFocus int) (bool, tea.Cmd) {
	action, nextFocus := classifyFormKey(key, focus, lastFocus, toggleFocus)
	switch action {
	case tuiFormKeyClose:
		m.closeDialog()
		return true, nil
	case tuiFormKeyFocus:
		return true, m.focusPickerForm(nextFocus)
	case tuiFormKeyToggle:
		m.togglePickerFormChoice()
		return true, nil
	case tuiFormKeySubmit:
		return true, m.submitPickerForm()
	default:
		return false, nil
	}
}

func (m *sandboxTUIModel) focusPickerForm(index int) tea.Cmd {
	switch m.dialog {
	case tuiShareAddDialog:
		m.shareSandbox.open = false
		return m.focusShare(index)
	case tuiPortPublishDialog:
		m.portSandbox.open = false
		return m.focusPort(index)
	case tuiNetworkPolicyDialog:
		m.policySandbox.open = false
		return m.focusNetworkPolicy(index)
	default:
		return nil
	}
}

func (m *sandboxTUIModel) togglePickerFormChoice() {
	switch m.dialog {
	case tuiShareAddDialog:
		m.shareRO = !m.shareRO
	case tuiPortPublishDialog:
		m.portUDP = !m.portUDP
	case tuiNetworkPolicyDialog:
		m.policyLocal = !m.policyLocal
	}
}

func (m *sandboxTUIModel) submitPickerForm() tea.Cmd {
	var cmd tea.Cmd
	switch m.dialog {
	case tuiShareAddDialog:
		_, cmd = m.submitShare()
	case tuiPortPublishDialog:
		_, cmd = m.submitPort()
	case tuiNetworkPolicyDialog:
		_, cmd = m.submitNetworkPolicy()
	}
	return cmd
}

func (m *sandboxTUIModel) updateShareDialogKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	if m.shareFocus == 0 && m.shareSandbox.HandleKey(msg.String()) {
		return m, nil
	}
	if handled, cmd := m.applyPickerFormKey(msg.String(), m.shareFocus, 6, 5); handled {
		return m, cmd
	}

	var cmd tea.Cmd
	switch m.shareFocus {
	case 1:
		m.shareTag, cmd = m.shareTag.Update(msg)
	case 2:
		m.sharePath, cmd = m.sharePath.Update(msg)
	case 3:
		m.shareMount, cmd = m.shareMount.Update(msg)
	case 4:
		m.shareOwner, cmd = m.shareOwner.Update(msg)
	}
	m.formError = ""
	return m, cmd
}

func (m *sandboxTUIModel) openShareAddDialog(replace bool) tea.Cmd {
	target := m.shareTargetSandbox()
	if target == nil {
		return m.showToast(tuiToastInfo, "No eligible sandbox", "Wait for a starting sandbox to finish, or create one first.")
	}
	m.dialog = tuiShareAddDialog
	m.dialogScroll = 0
	m.formError = ""
	m.shareReplace = replace
	m.shareRO = true
	m.shareTag.Reset()
	m.sharePath.Reset()
	m.shareMount.Reset()
	m.shareOwner.Reset()
	preferred := target.Name
	if replace {
		if row := m.selectedMount(); row != nil && row.Error == "" {
			preferred = row.Sandbox
			m.shareTag.SetValue(row.Tag)
			m.sharePath.SetValue(row.Host)
			if row.Guest != "" && row.Guest != m.service.DefaultShareMount(row.Tag) {
				m.shareMount.SetValue(row.Guest)
			}
			m.shareRO = row.ReadOnly
			if row.UID != nil && row.GID != nil {
				m.shareOwner.SetValue(fmt.Sprintf("%d:%d", *row.UID, *row.GID))
			}
		}
	}
	m.shareSandbox.ResetWhere(m.sandboxes, preferred, func(sandbox tuiSandbox) bool {
		return sandbox.State == tuiRunning || sandbox.State == tuiStopped
	})
	m.resizeInputs()
	return m.focusShare(0)
}

func (m *sandboxTUIModel) focusShare(index int) tea.Cmd {
	m.shareFocus = clampInt(index, 0, 6)
	m.shareTag.Blur()
	m.sharePath.Blur()
	m.shareMount.Blur()
	m.shareOwner.Blur()
	m.ensureDialogFocusVisible()
	switch m.shareFocus {
	case 1:
		return m.shareTag.Focus()
	case 2:
		return m.sharePath.Focus()
	case 3:
		return m.shareMount.Focus()
	case 4:
		return m.shareOwner.Focus()
	default:
		return nil
	}
}

func (m *sandboxTUIModel) updatePortDialogKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	if m.portFocus == 0 && m.portSandbox.HandleKey(msg.String()) {
		return m, nil
	}
	if handled, cmd := m.applyPickerFormKey(msg.String(), m.portFocus, 4, 3); handled {
		return m, cmd
	}

	var cmd tea.Cmd
	switch m.portFocus {
	case 1:
		m.portBind, cmd = m.portBind.Update(msg)
	case 2:
		m.portGuest, cmd = m.portGuest.Update(msg)
	}
	m.formError = ""
	return m, cmd
}

func (m *sandboxTUIModel) openPortPublishDialog() tea.Cmd {
	target := m.runningTargetSandbox()
	if target == nil {
		return m.showToast(tuiToastInfo, "No running sandbox", "Start a sandbox before publishing a port.")
	}
	if !m.portSandbox.ResetWhere(m.sandboxes, target.Name, func(sandbox tuiSandbox) bool {
		return sandbox.State == tuiRunning && sandbox.Net && sandbox.GVProxy == ""
	}) {
		return m.showToast(tuiToastInfo, "No eligible sandbox", "Port publishing requires a running sandbox with the embedded netstack.")
	}
	m.dialog = tuiPortPublishDialog
	m.dialogScroll = 0
	m.formError = ""
	m.portUDP = false
	m.portBind.Reset()
	m.portGuest.Reset()
	m.resizeInputs()
	return m.focusPort(0)
}

func (m *sandboxTUIModel) focusPort(index int) tea.Cmd {
	m.portFocus = clampInt(index, 0, 4)
	m.portBind.Blur()
	m.portGuest.Blur()
	m.ensureDialogFocusVisible()
	switch m.portFocus {
	case 1:
		return m.portBind.Focus()
	case 2:
		return m.portGuest.Focus()
	default:
		return nil
	}
}

func (m *sandboxTUIModel) updateNetworkPolicyDialogKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	if m.policyFocus == 0 {
		before := m.policySandbox.Value()
		if m.policySandbox.HandleKey(msg.String()) {
			if m.policySandbox.Value() != before {
				m.syncNetworkPolicyFields()
			}
			return m, nil
		}
	}
	if handled, cmd := m.applyPickerFormKey(msg.String(), m.policyFocus, 3, 2); handled {
		return m, cmd
	}
	var cmd tea.Cmd
	if m.policyFocus == 1 {
		m.policyPath, cmd = m.policyPath.Update(msg)
	}
	m.formError = ""
	return m, cmd
}

func (m *sandboxTUIModel) openNetworkPolicyDialog() tea.Cmd {
	preferred := ""
	if row := m.selectedRule(); row != nil {
		preferred = row.Sandbox
	} else if sandbox := m.selected(); sandbox != nil {
		preferred = sandbox.Name
	}
	if !m.policySandbox.ResetWhere(m.sandboxes, preferred, func(sandbox tuiSandbox) bool {
		return sandbox.State == tuiRunning && sandbox.Net && sandbox.GVProxy == ""
	}) {
		return m.showToast(tuiToastInfo, "No eligible sandbox", "Live policy updates require a running sandbox with the embedded netstack.")
	}
	m.dialog = tuiNetworkPolicyDialog
	m.dialogScroll = 0
	m.formError = ""
	m.syncNetworkPolicyFields()
	m.resizeInputs()
	return m.focusNetworkPolicy(0)
}

func (m *sandboxTUIModel) openRuleAddDialog() tea.Cmd {
	preferred := ""
	if row := m.selectedTraffic(); row != nil {
		preferred = row.Sandbox
	}
	if !m.ruleSandbox.ResetWhere(m.sandboxes, preferred, func(sandbox tuiSandbox) bool {
		return sandbox.State != tuiStarting && sandbox.Net && sandbox.GVProxy == ""
	}) {
		return m.showToast(tuiToastInfo, "No eligible sandbox", "Rules require a network-enabled sandbox using the embedded netstack.")
	}
	m.dialog = tuiRuleAddDialog
	m.dialogScroll = 0
	m.formError = ""
	m.ruleTarget.Reset()
	m.rulePorts.Reset()
	m.ruleTarget.Placeholder = "203.0.113.10 or 203.0.113.0/24 (blank = all)"
	m.ruleTarget.CharLimit = 64
	m.ruleAction = "deny"
	m.ruleProtocol = "any"
	if row := m.selectedTraffic(); row != nil {
		if strings.EqualFold(row.Protocol, "dns") {
			m.ruleTarget.Placeholder = "pi.dev"
			m.ruleTarget.CharLimit = 253
			m.ruleTarget.SetValue(row.Host)
			m.ruleProtocol = "dns"
			m.ruleAction = "allow"
		} else {
			m.ruleTarget.SetValue(row.Address)
			switch row.Protocol {
			case "tcp", "udp", "icmp":
				m.ruleProtocol = row.Protocol
			}
			if row.Port != 0 && (m.ruleProtocol == "tcp" || m.ruleProtocol == "udp") {
				m.rulePorts.SetValue(strconv.Itoa(int(row.Port)))
			}
			if !row.Allowed {
				m.ruleAction = "allow"
			}
		}
	}
	m.resizeInputs()
	return m.focusRule(0)
}

func (m *sandboxTUIModel) updateRuleAddDialogKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	if m.ruleFocus == 0 && m.ruleSandbox.HandleKey(msg.String()) {
		return m, nil
	}
	key := msg.String()
	switch key {
	case "esc":
		m.closeDialog()
		return m, nil
	case "tab", "down":
		return m, m.advanceRuleFocus(1)
	case "shift+tab", "up":
		return m, m.advanceRuleFocus(-1)
	case "left", "right", " ", "space":
		switch m.ruleFocus {
		case 1:
			if m.ruleProtocol == "dns" {
				return m, nil
			}
			if m.ruleAction == "deny" {
				m.ruleAction = "allow"
			} else {
				m.ruleAction = "deny"
			}
			return m, nil
		case 3:
			if m.ruleProtocol == "dns" {
				return m, nil
			}
			delta := 1
			if key == "left" {
				delta = -1
			}
			m.cycleRuleProtocol(delta)
			if m.ruleProtocol != "tcp" && m.ruleProtocol != "udp" {
				m.rulePorts.Reset()
			}
			return m, nil
		}
	case "ctrl+enter":
		return m.submitRuleAdd()
	case "enter":
		if m.ruleFocus < 5 {
			return m, m.advanceRuleFocus(1)
		}
		return m.submitRuleAdd()
	}
	var cmd tea.Cmd
	switch m.ruleFocus {
	case 2:
		m.ruleTarget, cmd = m.ruleTarget.Update(msg)
	case 4:
		if m.ruleProtocol != "dns" {
			m.rulePorts, cmd = m.rulePorts.Update(msg)
		}
	}
	m.formError = ""
	return m, cmd
}

func (m *sandboxTUIModel) cycleRuleProtocol(delta int) {
	choices := []string{"any", "tcp", "udp", "icmp"}
	index := 0
	for i, choice := range choices {
		if choice == m.ruleProtocol {
			index = i
			break
		}
	}
	m.ruleProtocol = choices[(index+delta+len(choices))%len(choices)]
}

func (m *sandboxTUIModel) advanceRuleFocus(delta int) tea.Cmd {
	choices := []int{0, 1, 2, 3, 4, 5}
	if m.ruleProtocol == "dns" {
		choices = []int{0, 2, 5}
	}
	index := 0
	for i, choice := range choices {
		if choice == m.ruleFocus {
			index = i
			break
		}
	}
	index = (index + delta + len(choices)) % len(choices)
	return m.focusRule(choices[index])
}

func (m sandboxTUIModel) ruleAddButtonLabel() string {
	if m.ruleProtocol == "dns" {
		return "Allow domain"
	}
	return "Add rule"
}

func (m *sandboxTUIModel) focusRule(index int) tea.Cmd {
	m.ruleFocus = clampInt(index, 0, 5)
	m.ruleSandbox.open = false
	m.ruleTarget.Blur()
	m.rulePorts.Blur()
	m.ensureDialogFocusVisible()
	switch m.ruleFocus {
	case 2:
		return m.ruleTarget.Focus()
	case 4:
		return m.rulePorts.Focus()
	default:
		return nil
	}
}

func (m *sandboxTUIModel) submitRuleAdd() (tea.Model, tea.Cmd) {
	request := dashboardapi.RuleRequest{
		Sandbox: m.ruleSandbox.Value(), Action: m.ruleAction,
		Target: strings.TrimSpace(m.ruleTarget.Value()), Proto: m.ruleProtocol,
		Ports: strings.TrimSpace(m.rulePorts.Value()),
	}
	if request.Sandbox == "" {
		m.formError = "no eligible sandbox"
		return m, m.focusRule(0)
	}
	if err := m.service.ValidateNetworkRule(request); err != nil {
		m.formError = err.Error()
		switch dashboardErrorField(err) {
		case "action":
			return m, m.focusRule(1)
		case "target":
			return m, m.focusRule(2)
		case "protocol":
			return m, m.focusRule(3)
		default:
			return m, m.focusRule(4)
		}
	}
	m.closeDialog()
	m.busyAction = "rule add"
	m.busyName = request.Sandbox
	return m, tea.Batch(addNetworkRuleCmd(m.service, request), m.ensureAnimation())
}

func (m *sandboxTUIModel) removeSelectedRule() (tea.Model, tea.Cmd) {
	row := m.selectedRule()
	if row == nil {
		m.closeDialog()
		return m, nil
	}
	m.closeDialog()
	m.busyAction = "rule remove"
	m.busyName = row.Sandbox + "/" + row.Source
	return m, tea.Batch(removeNetworkRuleCmd(m.service, *row), m.ensureAnimation())
}

func (m *sandboxTUIModel) removeSelectedTrafficRule() (tea.Model, tea.Cmd) {
	row := m.selectedTraffic()
	if row == nil {
		return m, nil
	}
	m.busyAction = "rule remove"
	m.busyName = row.Sandbox + "/" + row.Address
	return m, tea.Batch(removeTrafficRuleCmd(m.service, *row), m.ensureAnimation())
}

func (m *sandboxTUIModel) openSecretAddDialog() tea.Cmd {
	preferred := ""
	if row := m.selectedSecret(); row != nil {
		preferred = row.Sandbox
	}
	if !m.secretSandbox.Reset(m.sandboxes, preferred) {
		return m.showToast(tuiToastInfo, "No running sandbox", "Start a sandbox before adding an in-memory secret.")
	}
	m.dialog = tuiSecretAddDialog
	m.dialogScroll = 0
	m.formError = ""
	m.secretName.Reset()
	m.secretValue.Reset()
	m.resizeInputs()
	return m.focusSecret(0)
}

func (m *sandboxTUIModel) updateSecretAddDialogKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	if m.secretFocus == 0 && m.secretSandbox.HandleKey(msg.String()) {
		return m, nil
	}
	switch msg.String() {
	case "esc":
		m.closeDialog()
		return m, nil
	case "tab", "down":
		return m, m.focusSecret((m.secretFocus + 1) % 4)
	case "shift+tab", "up":
		return m, m.focusSecret((m.secretFocus + 3) % 4)
	case "ctrl+enter":
		return m.submitSecretAdd()
	case "enter":
		if m.secretFocus < 3 {
			return m, m.focusSecret(m.secretFocus + 1)
		}
		return m.submitSecretAdd()
	}
	var cmd tea.Cmd
	switch m.secretFocus {
	case 1:
		m.secretName, cmd = m.secretName.Update(msg)
	case 2:
		m.secretValue, cmd = m.secretValue.Update(msg)
	}
	m.formError = ""
	return m, cmd
}

func (m *sandboxTUIModel) focusSecret(index int) tea.Cmd {
	m.secretFocus = clampInt(index, 0, 3)
	m.secretSandbox.open = false
	m.secretName.Blur()
	m.secretValue.Blur()
	m.ensureDialogFocusVisible()
	switch m.secretFocus {
	case 1:
		return m.secretName.Focus()
	case 2:
		return m.secretValue.Focus()
	default:
		return nil
	}
}

func (m *sandboxTUIModel) submitSecretAdd() (tea.Model, tea.Cmd) {
	request := dashboardapi.SecretRequest{
		Sandbox: m.secretSandbox.Value(), Name: strings.TrimSpace(m.secretName.Value()), Value: secret.Value(m.secretValue.Value()),
	}
	if err := m.service.ValidateSecret(request); err != nil {
		m.formError = err.Error()
		switch dashboardErrorField(err) {
		case "sandbox":
			return m, m.focusSecret(0)
		case "name":
			return m, m.focusSecret(1)
		default:
			return m, m.focusSecret(2)
		}
	}
	m.secretValue.Reset()
	m.closeDialog()
	m.busyAction = "secret add"
	m.busyName = request.Sandbox + "/" + request.Name
	return m, tea.Batch(addSecretCmd(m.service, request), m.ensureAnimation())
}

func (m *sandboxTUIModel) removeSelectedSecret() (tea.Model, tea.Cmd) {
	row := m.selectedSecret()
	if row == nil {
		m.closeDialog()
		return m, nil
	}
	m.closeDialog()
	m.busyAction = "secret remove"
	m.busyName = row.Sandbox + "/" + row.Name
	return m, tea.Batch(removeSecretCmd(m.service, *row), m.ensureAnimation())
}

func (m *sandboxTUIModel) syncNetworkPolicyFields() {
	m.policyPath.Reset()
	m.policyLocal = false
	if sandbox := m.sandboxNamed(m.policySandbox.Value()); sandbox != nil {
		m.policyPath.SetValue(sandbox.NetPolicy)
		m.policyLocal = sandbox.AllowLocal
	}
}

func (m *sandboxTUIModel) focusNetworkPolicy(index int) tea.Cmd {
	m.policyFocus = clampInt(index, 0, 3)
	m.policyPath.Blur()
	m.ensureDialogFocusVisible()
	if m.policyFocus == 1 {
		return m.policyPath.Focus()
	}
	return nil
}

func (m *sandboxTUIModel) submitNetworkPolicy() (tea.Model, tea.Cmd) {
	name := m.policySandbox.Value()
	if name == "" {
		m.formError = "no eligible running sandbox"
		return m, m.focusNetworkPolicy(0)
	}
	path := strings.TrimSpace(m.policyPath.Value())
	if err := m.service.ValidateNetworkPolicy(path, m.policyLocal); err != nil {
		m.formError = err.Error()
		return m, m.focusNetworkPolicy(1)
	}
	m.dialog = tuiNoDialog
	m.dialogScroll = 0
	m.busyAction = "netpolicy set"
	m.busyName = name
	return m, tea.Batch(setSandboxNetworkPolicyCmd(m.service, name, path, m.policyLocal), m.ensureAnimation())
}

// portSpecFromDialog composes [IP:]HOST:GUEST[/udp] from the dialog fields.
// Split out for tests: blank bind = auto host port on loopback, a bare
// number = loopback + that port, ip:port widens the bind explicitly. Both
// fields are validated strictly BEFORE spec composition: the guest field is
// digits-only, so it can never smuggle an address (e.g. "[::]:80") into the
// bind position, and a bind address must parse as an IP.
func (m *sandboxTUIModel) portSpecFromDialog() (string, error) {
	return m.service.PlanPort(dashboardapi.PortRequest{
		Bind: m.portBind.Value(), Guest: m.portGuest.Value(), UDP: m.portUDP,
	})
}

func (m *sandboxTUIModel) submitPort() (tea.Model, tea.Cmd) {
	targetName := m.portSandbox.Value()
	if targetName == "" {
		m.formError = "no running sandbox available"
		return m, m.focusPort(0)
	}
	spec, err := m.portSpecFromDialog()
	if err != nil {
		m.formError = err.Error()
		if dashboardErrorField(err) == "guest" {
			return m, m.focusPort(2)
		}
		return m, m.focusPort(1)
	}
	return m.beginAction("port publish", targetName+"/"+spec, []string{"ports", "publish", targetName, spec}, false)
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
	targetName := m.shareSandbox.Value()
	target := m.sandboxNamed(targetName)
	if target == nil || target.State == tuiStarting {
		m.formError = "no eligible sandbox available"
		return m, m.focusShare(0)
	}
	currentGuest := ""
	if row := m.selectedMount(); row != nil {
		currentGuest = row.Guest
	}
	plan, err := m.service.PlanShare(dashboardapi.ShareRequest{
		Sandbox: targetName, Tag: strings.TrimSpace(m.shareTag.Value()),
		Path: strings.TrimSpace(m.sharePath.Value()), Mountpoint: strings.TrimSpace(m.shareMount.Value()),
		Owner: m.shareOwner.Value(), ReadOnly: m.shareRO, Replace: m.shareReplace,
		Running: target.State == tuiRunning, CurrentGuest: currentGuest,
	})
	if err != nil {
		m.formError = err.Error()
		switch dashboardErrorField(err) {
		case "tag":
			return m, m.focusShare(1)
		case "path":
			return m, m.focusShare(2)
		case "mountpoint":
			return m, m.focusShare(3)
		case "owner":
			return m, m.focusShare(4)
		default:
			return m, m.focusShare(0)
		}
	}
	if !plan.Live {
		m.dialog = tuiNoDialog
		m.dialogScroll = 0
		m.busyAction = "share configure"
		m.busyName = plan.Sandbox + "/" + plan.Tag
		return m, tea.Batch(
			configureSandboxShareCmd(m.service, plan, target.State == tuiRunning),
			m.ensureAnimation(),
		)
	}
	argv := []string{"share", "add"}
	if plan.Replace {
		argv = append(argv, "--replace")
	}
	argv = append(argv, plan.Sandbox, plan.Spec)
	action := "share add"
	if plan.Replace {
		action = "share replace"
	}
	return m.beginAction(action, plan.Sandbox+"/"+plan.Tag, argv, false)
}

func (m *sandboxTUIModel) removeSelectedShare() (tea.Model, tea.Cmd) {
	row := m.selectedMount()
	if row == nil || row.Error != "" {
		m.closeDialog()
		return m, nil
	}
	m.closeDialog()
	m.busyAction = "share remove"
	m.busyName = row.Sandbox + "/" + row.Tag
	return m, tea.Batch(removeSandboxShareCmd(m.service, *row), m.ensureAnimation())
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
	m.dialogScroll = 0
	m.confirmRemove = false
	m.formError = ""
	m.createName.Blur()
	m.createImage.Blur()
	m.shareTag.Blur()
	m.sharePath.Blur()
	m.shareOwner.Blur()
	m.shareSandbox.open = false
	m.portBind.Blur()
	m.portGuest.Blur()
	m.portSandbox.open = false
	m.policyPath.Blur()
	m.policySandbox.open = false
	m.ruleTarget.Blur()
	m.rulePorts.Blur()
	m.ruleSandbox.open = false
	m.secretName.Blur()
	m.secretValue.Blur()
	m.secretValue.Reset()
	m.secretSandbox.open = false
	m.shareReplace = false
}

func (m sandboxTUIModel) dialogViewportHeight() int {
	if m.dialog == tuiNoDialog {
		return 1
	}
	_, height, _, _ := m.dialogMeasured(tuiThemeFor(m.dark), m.dialog)
	return maxInt(1, height-4)
}

func (m sandboxTUIModel) dialogMaxScroll() int {
	if m.dialog == tuiNoDialog {
		return 0
	}
	_, height, content, _ := m.dialogMeasured(tuiThemeFor(m.dark), m.dialog)
	return maxInt(0, lipgloss.Height(content)-maxInt(1, height-4))
}

func (m *sandboxTUIModel) scrollDialog(delta int) {
	m.dialogScroll = clampInt(m.dialogScroll+delta, 0, m.dialogMaxScroll())
}

// ensureDialogFocusVisible follows keyboard focus through forms whose content
// is taller than the terminal. Manual wheel scrolling remains undisturbed
// until focus changes again.
func (m *sandboxTUIModel) ensureDialogFocusVisible() {
	if m.dialog == tuiNoDialog {
		m.dialogScroll = 0
		return
	}
	_, height, content, _ := m.dialogMeasured(tuiThemeFor(m.dark), m.dialog)
	viewport := maxInt(1, height-4)
	maxScroll := maxInt(0, lipgloss.Height(content)-viewport)
	m.dialogScroll = clampInt(m.dialogScroll, 0, maxScroll)
	needle, fromEnd := m.dialogFocusTarget()
	if needle == "" || maxScroll == 0 {
		return
	}
	if m.dialogFocusAtStart() {
		m.dialogScroll = 0
		return
	}
	lines := strings.Split(ansi.Strip(content), "\n")
	line := -1
	if fromEnd {
		for i := len(lines) - 1; i >= 0; i-- {
			if strings.Contains(lines[i], needle) {
				line = i
				break
			}
		}
	} else {
		for i := minInt(2, len(lines)); i < len(lines); i++ {
			if strings.Contains(lines[i], needle) {
				line = i
				break
			}
		}
	}
	if line < 0 {
		return
	}
	if line < m.dialogScroll+1 {
		m.dialogScroll = maxInt(0, line-1)
	}
	// Keep the focused label plus its value/control and one context row in
	// view. Buttons resolve from the end and naturally clamp to maxScroll.
	if line+2 >= m.dialogScroll+viewport {
		m.dialogScroll = minInt(maxScroll, line+3-viewport)
	}
}

func (m sandboxTUIModel) dialogFocusAtStart() bool {
	switch m.dialog {
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
		return choose(m.createFocus, []string{"Name", "OCI image", "Runtime", "Kernel", "CPUs", "Memory", "Persistent disk", "Process isolation", "Create"}), m.createFocus == 8
	case tuiEditDialog:
		return choose(m.editFocus, []string{"CPUs", "Memory", "Process isolation", "Save"}), m.editFocus == 3
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
	default:
		return "", false
	}
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
	m.shareMount.SetWidth(shareFieldWidth)
	m.shareOwner.SetWidth(shareFieldWidth)
	portWidth, _ := m.dialogSize(tuiPortPublishDialog)
	portFieldWidth := maxInt(12, portWidth-10)
	m.portBind.SetWidth(portFieldWidth)
	m.portGuest.SetWidth(portFieldWidth)
	policyWidth, _ := m.dialogSize(tuiNetworkPolicyDialog)
	m.policyPath.SetWidth(maxInt(12, policyWidth-10))
	ruleWidth, _ := m.dialogSize(tuiRuleAddDialog)
	m.ruleTarget.SetWidth(maxInt(12, ruleWidth-10))
	m.rulePorts.SetWidth(maxInt(12, ruleWidth-10))
	secretWidth, _ := m.dialogSize(tuiSecretAddDialog)
	m.secretName.SetWidth(maxInt(12, secretWidth-10))
	m.secretValue.SetWidth(maxInt(12, secretWidth-10))
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
	m.shareMount.SetStyles(styles)
	m.shareOwner.SetStyles(styles)
	m.portBind.SetStyles(styles)
	m.portGuest.SetStyles(styles)
	m.policyPath.SetStyles(styles)
	m.ruleTarget.SetStyles(styles)
	m.rulePorts.SetStyles(styles)
	m.secretName.SetStyles(styles)
	m.secretValue.SetStyles(styles)
	m.spinner.Style = lipgloss.NewStyle().Foreground(theme.accent)
}

type tuiFormRowSpan struct {
	first int
	last  int
}

func (span tuiFormRowSpan) contains(row int) bool {
	return row >= span.first && row <= span.last
}

func dashboardErrorField(err error) string {
	var fieldErr *dashboardapi.FieldError
	if errors.As(err, &fieldErr) {
		return fieldErr.Field
	}
	return ""
}

type tuiFormRowLayout struct {
	compact  []tuiFormRowSpan
	spacious []tuiFormRowSpan
}

var (
	createDialogRows = tuiFormRowLayout{
		compact:  []tuiFormRowSpan{{5, 7}, {9, 11}, {13, 14}, {15, 16}, {17, 19}, {20, 22}, {23, 25}, {26, 27}},
		spacious: []tuiFormRowSpan{{6, 9}, {11, 14}, {16, 17}, {19, 20}, {22, 23}, {25, 26}, {28, 29}, {31, 32}},
	}
	shareDialogRows = tuiFormRowLayout{
		compact:  []tuiFormRowSpan{{5, 8}, {9, 12}, {13, 16}, {17, 20}, {21, 24}, {25, 26}},
		spacious: []tuiFormRowSpan{{6, 9}, {11, 14}, {16, 19}, {21, 24}, {26, 29}, {31, 32}},
	}
	portDialogRows = tuiFormRowLayout{
		compact:  []tuiFormRowSpan{{5, 8}, {9, 12}, {13, 16}, {17, 19}},
		spacious: []tuiFormRowSpan{{6, 9}, {11, 14}, {16, 19}, {21, 23}},
	}
	policyDialogRows = tuiFormRowLayout{
		compact:  []tuiFormRowSpan{{5, 8}, {9, 12}, {13, 13}},
		spacious: []tuiFormRowSpan{{6, 9}, {11, 14}, {16, 16}},
	}
	ruleDialogRows = tuiFormRowLayout{
		compact:  []tuiFormRowSpan{{5, 8}, {9, 10}, {11, 14}, {15, 16}, {17, 20}},
		spacious: []tuiFormRowSpan{{6, 9}, {11, 12}, {14, 17}, {19, 20}, {22, 25}},
	}
	secretDialogRows = tuiFormRowLayout{
		compact:  []tuiFormRowSpan{{5, 8}, {9, 12}, {13, 16}},
		spacious: []tuiFormRowSpan{{6, 9}, {11, 14}, {16, 19}},
	}
)

func (m sandboxTUIModel) formControlRows(layout tuiFormRowLayout, afterFirstOffset int) []tuiFormRowSpan {
	var source []tuiFormRowSpan
	if m.formDialogsSpacious() {
		source = layout.spacious
	} else {
		source = layout.compact
	}
	rows := append([]tuiFormRowSpan(nil), source...)
	for i := 1; i < len(rows); i++ {
		rows[i].first += afterFirstOffset
		rows[i].last += afterFirstOffset
	}
	return rows
}

// dialogButtonHit resolves the button from the rendered dialog instead of
// duplicating footer row arithmetic in every form. Padding around the label is
// included so the visible button and its click target stay together when a
// form gains or loses rows.
func (m sandboxTUIModel) dialogButtonHit(mouse tea.Mouse, bounds tuiRect, label string) bool {
	rect, ok := m.dialogButtonRect(bounds, label)
	return ok && rect.contains(mouse.X, mouse.Y)
}

func (m sandboxTUIModel) dialogButtonRect(bounds tuiRect, label string) (tuiRect, bool) {
	lines := strings.Split(ansi.Strip(m.renderDialog(tuiThemeFor(m.dark))), "\n")
	for row := len(lines) - 1; row >= 0; row-- {
		byteOffset := strings.LastIndex(lines[row], label)
		if byteOffset < 0 {
			continue
		}
		start := maxInt(0, lipgloss.Width(lines[row][:byteOffset])-2)
		end := lipgloss.Width(lines[row][:byteOffset+len(label)]) + 2
		return tuiRect{x: bounds.x + start, y: bounds.y + row, w: end - start, h: 1}, true
	}
	return tuiRect{}, false
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
		return m.updateDialogMouseClick(mouse)
	}
	return m.updateDashboardMouseClick(mouse)
}

func (m *sandboxTUIModel) updateDialogMouseClick(mouse tea.Mouse) (tea.Model, tea.Cmd) {
	bounds := m.dialogBounds(m.dialog)
	if !bounds.contains(mouse.X, mouse.Y) {
		m.closeDialog()
		return m, nil
	}
	if mouse.X == bounds.x+bounds.w-2 && mouse.Y >= bounds.y+2 && mouse.Y < bounds.y+bounds.h-2 {
		viewport := m.dialogViewportHeight()
		maxScroll := m.dialogMaxScroll()
		if maxScroll > 0 {
			trackRow := clampInt(mouse.Y-(bounds.y+2), 0, viewport-1)
			m.dialogScroll = trackRow * maxScroll / maxInt(1, viewport-1)
			return m, nil
		}
	}
	// Every dialog has a close glyph in its title row (the dialog has one
	// row of border and one row of vertical padding above it).
	if mouse.Y >= bounds.y+1 && mouse.Y <= bounds.y+3 && mouse.X >= bounds.x+bounds.w-6 {
		m.closeDialog()
		return m, nil
	}
	switch m.dialog {
	case tuiRemoveDialog, tuiShareRemoveDialog, tuiPortUnpublishDialog, tuiRuleRemoveDialog, tuiSecretRemoveDialog, tuiUpdateDialog:
		return m.updateConfirmationDialogMouse(mouse, bounds)
	case tuiCreateDialog:
		return m.updateCreateDialogMouse(mouse, bounds)
	case tuiEditDialog:
		return m.updateEditDialogMouse(mouse, bounds)
	case tuiShareAddDialog:
		return m.updateShareDialogMouse(mouse, bounds)
	case tuiPortPublishDialog:
		return m.updatePortDialogMouse(mouse, bounds)
	case tuiNetworkPolicyDialog:
		return m.updateNetworkPolicyDialogMouse(mouse, bounds)
	case tuiRuleAddDialog:
		return m.updateRuleAddDialogMouse(mouse, bounds)
	case tuiSecretAddDialog:
		return m.updateSecretAddDialogMouse(mouse, bounds)
	default:
		return m, nil
	}
}

func (m *sandboxTUIModel) updateConfirmationDialogMouse(mouse tea.Mouse, bounds tuiRect) (tea.Model, tea.Cmd) {
	if m.dialogButtonHit(mouse, bounds, "Cancel") {
		m.confirmRemove = false
		m.closeDialog()
		return m, nil
	}
	if action := m.confirmationActionLabel(); action != "" && m.dialogButtonHit(mouse, bounds, action) {
		m.confirmRemove = true
		return m.submitConfirmationDialog()
	}
	return m, nil
}

func (m sandboxTUIModel) confirmationActionLabel() string {
	switch m.dialog {
	case tuiRemoveDialog, tuiShareRemoveDialog, tuiRuleRemoveDialog:
		return "Remove"
	case tuiPortUnpublishDialog:
		return "Unpublish"
	case tuiSecretRemoveDialog:
		return "Delete"
	case tuiUpdateDialog:
		return "Update"
	default:
		return ""
	}
}

func (m *sandboxTUIModel) updateCreateDialogMouse(mouse tea.Mouse, bounds tuiRect) (tea.Model, tea.Cmd) {
	// Resolve the footer from the rendered dialog before consulting the
	// approximate field-row ranges. In compact terminals the Create button can
	// share a row covered by the memory slider's generous mouse target.
	if m.dialogButtonHit(mouse, bounds, "Create") {
		m.createFocus = 8
		return m.submitCreate()
	}
	relY := mouse.Y - bounds.y + m.dialogScroll
	rows := m.formControlRows(createDialogRows, 0)
	switch {
	case rows[0].contains(relY):
		return m, m.focusCreate(0)
	case rows[1].contains(relY):
		return m, m.focusCreate(1)
	case rows[2].contains(relY):
		m.createFocus = 2
		m.adjustCreateChoice(1)
	case rows[3].contains(relY):
		m.createFocus = 3
		m.cycleCreateKernel(1)
	case rows[4].contains(relY):
		m.setSliderFromMouse(&m.createCPUs, bounds, mouse.X, "CPU")
		return m, m.focusCreate(4)
	case rows[5].contains(relY):
		m.setSliderFromMouse(&m.createMemory, bounds, mouse.X, "MiB")
		return m, m.focusCreate(5)
	case rows[6].contains(relY):
		m.setSliderFromMouse(&m.createDisk, bounds, mouse.X, "MiB")
		return m, m.focusCreate(6)
	case rows[7].contains(relY):
		m.createFocus = 7
		m.createIsolation = cycleIsolation(m.createIsolation, 1)
	}
	return m, nil
}

func (m *sandboxTUIModel) updateEditDialogMouse(mouse tea.Mouse, bounds tuiRect) (tea.Model, tea.Cmd) {
	// Find the rendered footer first: at compact heights its hitbox can share
	// rows with the deliberately generous field targets below.
	if m.dialogButtonHit(mouse, bounds, "Save") {
		m.editFocus = 3
		return m.submitEdit()
	}
	relY := mouse.Y - bounds.y + m.dialogScroll
	switch {
	case relY >= 6 && relY <= 8:
		m.setSliderFromMouse(&m.editCPUs, bounds, mouse.X, "CPU")
		return m, m.focusEdit(0)
	case relY >= 10 && relY <= 12:
		m.setSliderFromMouse(&m.editMemory, bounds, mouse.X, "MiB")
		return m, m.focusEdit(1)
	case relY >= 14 && relY <= 16:
		m.editFocus = 2
		m.editIsolation = cycleIsolation(m.editIsolation, 1)
	default:
		return m, nil
	}
	return m, nil
}

func (m *sandboxTUIModel) updateShareDialogMouse(mouse tea.Mouse, bounds tuiRect) (tea.Model, tea.Cmd) {
	relY := mouse.Y - bounds.y + m.dialogScroll
	rows := m.formControlRows(shareDialogRows, m.shareSandbox.menuHeight())
	if m.shareSandbox.open && m.shareSandbox.chooseVisible(relY-rows[0].last-2) {
		return m, nil
	}
	_, _, buttonLabel := m.shareDialogCopy()
	switch {
	case rows[0].contains(relY):
		m.shareSandbox.Toggle()
		return m, m.focusShare(0)
	case rows[1].contains(relY):
		return m, m.focusShare(1)
	case rows[2].contains(relY):
		return m, m.focusShare(2)
	case rows[3].contains(relY):
		return m, m.focusShare(3)
	case rows[4].contains(relY):
		return m, m.focusShare(4)
	case rows[5].contains(relY):
		m.shareFocus = 5
		m.shareRO = !m.shareRO
	case m.dialogButtonHit(mouse, bounds, buttonLabel):
		m.shareFocus = 6
		return m.submitShare()
	}
	return m, nil
}

func (m *sandboxTUIModel) updatePortDialogMouse(mouse tea.Mouse, bounds tuiRect) (tea.Model, tea.Cmd) {
	relY := mouse.Y - bounds.y + m.dialogScroll
	rows := m.formControlRows(portDialogRows, m.portSandbox.menuHeight())
	if m.portSandbox.open && m.portSandbox.chooseVisible(relY-rows[0].last-2) {
		return m, nil
	}
	switch {
	case rows[0].contains(relY):
		m.portSandbox.Toggle()
		return m, m.focusPort(0)
	case rows[1].contains(relY):
		return m, m.focusPort(1)
	case rows[2].contains(relY):
		return m, m.focusPort(2)
	case rows[3].contains(relY):
		m.portFocus = 3
		m.portUDP = !m.portUDP
	case m.dialogButtonHit(mouse, bounds, "Publish"):
		m.portFocus = 4
		return m.submitPort()
	}
	return m, nil
}

func (m *sandboxTUIModel) updateNetworkPolicyDialogMouse(mouse tea.Mouse, bounds tuiRect) (tea.Model, tea.Cmd) {
	relY := mouse.Y - bounds.y + m.dialogScroll
	rows := m.formControlRows(policyDialogRows, m.policySandbox.menuHeight())
	before := m.policySandbox.Value()
	if m.policySandbox.open && m.policySandbox.chooseVisible(relY-rows[0].last-2) {
		if m.policySandbox.Value() != before {
			m.syncNetworkPolicyFields()
		}
		return m, nil
	}
	switch {
	case rows[0].contains(relY):
		m.policySandbox.Toggle()
		return m, m.focusNetworkPolicy(0)
	case rows[1].contains(relY):
		return m, m.focusNetworkPolicy(1)
	case rows[2].contains(relY):
		m.policyFocus = 2
		m.policyLocal = !m.policyLocal
	case m.dialogButtonHit(mouse, bounds, "Apply"):
		m.policyFocus = 3
		return m.submitNetworkPolicy()
	}
	return m, nil
}

func (m *sandboxTUIModel) updateRuleAddDialogMouse(mouse tea.Mouse, bounds tuiRect) (tea.Model, tea.Cmd) {
	relY := mouse.Y - bounds.y + m.dialogScroll
	rows := m.formControlRows(ruleDialogRows, m.ruleSandbox.menuHeight())
	if m.ruleSandbox.open && m.ruleSandbox.chooseVisible(relY-rows[0].last-2) {
		return m, nil
	}
	// DNS's compact ports explanation occupies the same approximate rows as
	// the footer. Resolve the real rendered button before broad field hitboxes.
	if m.dialogButtonHit(mouse, bounds, m.ruleAddButtonLabel()) {
		m.ruleFocus = 5
		return m.submitRuleAdd()
	}
	switch {
	case rows[0].contains(relY):
		m.ruleSandbox.Toggle()
		return m, m.focusRule(0)
	case rows[1].contains(relY):
		if m.ruleProtocol == "dns" {
			return m, nil
		}
		m.ruleFocus = 1
		if m.ruleAction == "deny" {
			m.ruleAction = "allow"
		} else {
			m.ruleAction = "deny"
		}
	case rows[2].contains(relY):
		return m, m.focusRule(2)
	case rows[3].contains(relY):
		if m.ruleProtocol == "dns" {
			return m, nil
		}
		m.ruleFocus = 3
		m.cycleRuleProtocol(1)
		if m.ruleProtocol != "tcp" && m.ruleProtocol != "udp" {
			m.rulePorts.Reset()
		}
	case rows[4].contains(relY):
		if m.ruleProtocol == "dns" {
			return m, nil
		}
		return m, m.focusRule(4)
	}
	return m, nil
}

func (m *sandboxTUIModel) updateSecretAddDialogMouse(mouse tea.Mouse, bounds tuiRect) (tea.Model, tea.Cmd) {
	relY := mouse.Y - bounds.y + m.dialogScroll
	rows := m.formControlRows(secretDialogRows, m.secretSandbox.menuHeight())
	if m.secretSandbox.open && m.secretSandbox.chooseVisible(relY-rows[0].last-2) {
		return m, nil
	}
	switch {
	case rows[0].contains(relY):
		m.secretSandbox.Toggle()
		return m, m.focusSecret(0)
	case rows[1].contains(relY):
		return m, m.focusSecret(1)
	case rows[2].contains(relY):
		return m, m.focusSecret(2)
	case m.dialogButtonHit(mouse, bounds, "Add secret"):
		m.secretFocus = 3
		return m.submitSecretAdd()
	}
	return m, nil
}

func (m *sandboxTUIModel) updateDashboardMouseClick(mouse tea.Mouse) (tea.Model, tea.Cmd) {
	if m.updateTabMouseClick(mouse) {
		return m, nil
	}
	if cmd, handled := m.updateMenuMouseClick(mouse); handled {
		return m, cmd
	}
	if m.busyAction != "" {
		return m, nil
	}
	if m.page != tuiSandboxesPage {
		m.updateTableMouseClick(mouse)
		return m, nil
	}
	return m.updateCardMouseClick(mouse)
}

func (m *sandboxTUIModel) updateTabMouseClick(mouse tea.Mouse) bool {
	// Dashboard tabs are both keyboard-addressable and clickable.
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
				return true
			}
		}
	}
	return false
}

func (m *sandboxTUIModel) updateMenuMouseClick(mouse tea.Mouse) (tea.Cmd, bool) {
	// The menu bar exposes the same primary actions as the reference CLI:
	// New and Help are both keyboard shortcuts and mouse targets.
	if mouse.Y != 1 {
		return nil, false
	}
	rects := m.menuItemRects(m.width)
	if rects["help"].contains(mouse.X, mouse.Y) {
		m.dialog = tuiHelpDialog
		m.dialogScroll = 0
		return nil, true
	}
	if rects["new"].contains(mouse.X, mouse.Y) && m.busyAction == "" {
		return m.openCreateDialog(), true
	}
	if rects["update"].contains(mouse.X, mouse.Y) && m.busyAction == "" && m.updateStatus.Available {
		m.dialog = tuiUpdateDialog
		m.dialogScroll = 0
		m.confirmRemove = false
		return nil, true
	}
	return nil, false
}

func (m *sandboxTUIModel) updateTableMouseClick(mouse tea.Mouse) {
	layout := m.dashboardLayout()
	rowY := layout.contentY + tuiTableHeaderHeight
	if mouse.Y < rowY || mouse.Y >= rowY+m.tableVisibleRows() {
		return
	}
	index := mouse.Y - rowY
	cursor, scroll, count := m.tableState()
	if cursor == nil {
		return
	}
	index += *scroll
	if index >= 0 && index < count {
		*cursor = index
		m.ensureTableCursorVisible()
	}
}

func (m *sandboxTUIModel) updateCardMouseClick(mouse tea.Mouse) (tea.Model, tea.Cmd) {
	layout := m.dashboardLayout()
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

func (m *sandboxTUIModel) setSliderFromMouse(slider *resourceSlider, bounds tuiRect, mouseX int, suffix string) {
	innerWidth := maxInt(10, bounds.w-6)
	barWidth := slider.barWidth(innerWidth, suffix)
	position := mouseX - (bounds.x + 3)
	if position >= 0 && position < barWidth {
		slider.SetFraction(position, barWidth)
	}
}

func (m *sandboxTUIModel) cardActionAt(x int, card tuiRect) (tea.Model, tea.Cmd) {
	if m.onNewCard() {
		return m, m.openCreateDialog()
	}
	selected := m.selected()
	if selected == nil {
		return m, nil
	}
	actions := []string{"primary", "edit", "delete"}
	if selected.State == tuiRunning {
		actions = []string{"primary", "toggle", "edit", "delete"}
	}
	innerX := clampInt(x-card.x-2, 0, maxInt(0, card.w-5))
	segment := maxInt(1, (card.w-4)/len(actions))
	index := minInt(len(actions)-1, innerX/segment)
	switch actions[index] {
	case "primary":
		return m.primaryAction()
	case "toggle":
		return m.toggleSelected()
	case "edit":
		return m, m.openEditDialog()
	case "delete":
		m.dialog = tuiRemoveDialog
		m.dialogScroll = 0
		m.confirmRemove = false
	}
	return m, nil
}

func (m *sandboxTUIModel) updateMouseWheel(mouse tea.Mouse) (tea.Model, tea.Cmd) {
	if m.dialog != tuiNoDialog {
		switch mouse.Button {
		case tea.MouseWheelUp:
			m.scrollDialog(-3)
		case tea.MouseWheelDown:
			m.scrollDialog(3)
		}
		return m, nil
	}
	if m.busyAction != "" {
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
