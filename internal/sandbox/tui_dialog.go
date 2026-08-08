package sandbox

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/ejpir/gantry/internal/shares"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
)

func (m *sandboxTUIModel) updateDialogKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	if msg.String() == "ctrl+c" {
		return m, func() tea.Msg { return tea.Quit() }
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
		return m, m.focusCreate((m.createFocus + 1) % 7)
	case "shift+tab", "up":
		return m, m.focusCreate((m.createFocus + 6) % 7)
	case "left", "h":
		if m.adjustCreateChoice(-1) {
			return m, nil
		}
	case "right", "l":
		if m.adjustCreateChoice(1) {
			return m, nil
		}
	case " ", "space":
		if m.createFocus == 2 || m.createFocus == 3 {
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
		if m.createFocus < 6 {
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
	if m.createCPUs.Value != 1 {
		argv = append(argv, "-cpus", strconv.Itoa(m.createCPUs.Value))
	}
	if m.createMemory.Value != 512 {
		argv = append(argv, "-mem", strconv.Itoa(m.createMemory.Value))
	}
	return argv
}

func (m *sandboxTUIModel) openCreateDialog() tea.Cmd {
	m.dialog = tuiCreateDialog
	m.formError = ""
	m.createName.Reset()
	m.createImage.Reset()
	m.createCPUs = newResourceSlider(1, maxSandboxVCPUs, 1, 1)
	m.createMemory = newResourceSlider(128, 65536, 128, 512)
	m.createRuntime = "crun"
	m.createKernels = createKernelChoices()
	m.createKernel = 0
	m.resizeInputs()
	return m.focusCreate(0)
}

func (m *sandboxTUIModel) focusCreate(index int) tea.Cmd {
	m.createFocus = clampInt(index, 0, 6)
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
	if err := validateSandboxResources(uint(m.createMemory.Value), m.createCPUs.Value); err != nil {
		m.formError = err.Error()
		if strings.Contains(err.Error(), "CPU") {
			return m, m.focusCreate(4)
		}
		return m, m.focusCreate(5)
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
	m.formError = ""
	m.editCPUs = newResourceSlider(1, maxSandboxVCPUs, 1, maxInt(1, selected.VCPUs))
	m.editMemory = newResourceSlider(128, 65536, 128, int(selected.MemMB))
	m.resizeInputs()
	return m.focusEdit(0)
}

func (m *sandboxTUIModel) updateEditDialogKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.closeDialog()
		return m, nil
	case "tab", "down":
		return m, m.focusEdit((m.editFocus + 1) % 3)
	case "shift+tab", "up":
		return m, m.focusEdit((m.editFocus + 2) % 3)
	case "left", "h":
		if m.adjustEditSlider(-1) {
			return m, nil
		}
	case "right", "l":
		if m.adjustEditSlider(1) {
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
		if m.editFocus < 2 {
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
	m.editFocus = clampInt(index, 0, 2)
	return nil
}

func (m *sandboxTUIModel) submitEdit() (tea.Model, tea.Cmd) {
	selected := m.selected()
	if selected == nil {
		m.closeDialog()
		return m, nil
	}
	memMB, vcpus := uint(m.editMemory.Value), m.editCPUs.Value
	err := validateSandboxResources(memMB, vcpus)
	if err != nil {
		m.formError = err.Error()
		if strings.Contains(err.Error(), "CPU") {
			return m, m.focusEdit(0)
		}
		return m, m.focusEdit(1)
	}
	m.dialog = tuiNoDialog
	m.busyAction = "edit"
	m.busyName = selected.Name
	return m, tea.Batch(saveSandboxResourcesCmd(selected.Name, memMB, vcpus, selected.State == tuiRunning), m.ensureAnimation())
}

func (m *sandboxTUIModel) updateShareDialogKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	if m.shareFocus == 0 && m.shareSandbox.HandleKey(msg.String()) {
		return m, nil
	}
	switch msg.String() {
	case "esc":
		m.closeDialog()
		return m, nil
	case "tab", "down":
		m.shareSandbox.open = false
		return m, m.focusShare((m.shareFocus + 1) % 7)
	case "shift+tab", "up":
		m.shareSandbox.open = false
		return m, m.focusShare((m.shareFocus + 6) % 7)
	case "left":
		if m.shareFocus == 5 {
			m.shareRO = !m.shareRO
			return m, nil
		}
	case "right":
		if m.shareFocus == 5 {
			m.shareRO = !m.shareRO
			return m, nil
		}
	case " ", "space":
		if m.shareFocus == 5 {
			m.shareRO = !m.shareRO
			return m, nil
		}
	case "ctrl+enter":
		return m.submitShare()
	case "enter":
		if m.shareFocus < 6 {
			return m, m.focusShare(m.shareFocus + 1)
		}
		return m.submitShare()
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
			if row.Guest != "" && row.Guest != shares.HubHostPath+"/"+row.Tag {
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
	switch msg.String() {
	case "esc":
		m.closeDialog()
		return m, nil
	case "tab", "down":
		m.portSandbox.open = false
		return m, m.focusPort((m.portFocus + 1) % 5)
	case "shift+tab", "up":
		m.portSandbox.open = false
		return m, m.focusPort((m.portFocus + 4) % 5)
	case "left":
		if m.portFocus == 3 {
			m.portUDP = !m.portUDP
			return m, nil
		}
	case "right":
		if m.portFocus == 3 {
			m.portUDP = !m.portUDP
			return m, nil
		}
	case " ", "space":
		if m.portFocus == 3 {
			m.portUDP = !m.portUDP
			return m, nil
		}
	case "ctrl+enter":
		return m.submitPort()
	case "enter":
		if m.portFocus < 4 {
			return m, m.focusPort(m.portFocus + 1)
		}
		return m.submitPort()
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
	switch msg.String() {
	case "esc":
		m.closeDialog()
		return m, nil
	case "tab", "down":
		m.policySandbox.open = false
		return m, m.focusNetworkPolicy((m.policyFocus + 1) % 4)
	case "shift+tab", "up":
		m.policySandbox.open = false
		return m, m.focusNetworkPolicy((m.policyFocus + 3) % 4)
	case "left", "right", " ", "space":
		if m.policyFocus == 2 {
			m.policyLocal = !m.policyLocal
			return m, nil
		}
	case "ctrl+enter":
		return m.submitNetworkPolicy()
	case "enter":
		if m.policyFocus < 3 {
			return m, m.focusNetworkPolicy(m.policyFocus + 1)
		}
		return m.submitNetworkPolicy()
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
	m.formError = ""
	m.syncNetworkPolicyFields()
	m.resizeInputs()
	return m.focusNetworkPolicy(0)
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
	if _, _, err := resolveNetworkPolicy(path, m.policyLocal); err != nil {
		m.formError = err.Error()
		return m, m.focusNetworkPolicy(1)
	}
	m.dialog = tuiNoDialog
	m.busyAction = "netpolicy set"
	m.busyName = name
	return m, tea.Batch(setSandboxNetworkPolicyCmd(name, path, m.policyLocal), m.ensureAnimation())
}

// portSpecFromDialog composes [IP:]HOST:GUEST[/udp] from the dialog fields.
// Split out for tests: blank bind = auto host port on loopback, a bare
// number = loopback + that port, ip:port widens the bind explicitly. Both
// fields are validated strictly BEFORE spec composition: the guest field is
// digits-only, so it can never smuggle an address (e.g. "[::]:80") into the
// bind position, and a bind address must parse as an IP.
func (m *sandboxTUIModel) portSpecFromDialog() (string, error) {
	guest := strings.TrimSpace(m.portGuest.Value())
	if _, err := parseStrictPort(guest, "guest port"); err != nil {
		return "", err
	}
	bind := strings.TrimSpace(m.portBind.Value())
	spec := guest // auto host port on loopback
	if bind != "" {
		host, port := bind, ""
		if h, p, err := net.SplitHostPort(bind); err == nil {
			host, port = h, p
		}
		if port != "" {
			if addr, err := netip.ParseAddr(host); err != nil || addr.Zone() != "" {
				return "", fmt.Errorf("host bind %q is not an IP address", host)
			}
			if _, err := parseStrictPort(port, "host port"); err != nil {
				return "", err
			}
			spec = bind + ":" + guest
		} else {
			if _, err := parseStrictPort(host, "host bind (want port or ip:port)"); err != nil {
				return "", err
			}
			spec = host + ":" + guest
		}
	}
	if m.portUDP {
		spec += "/udp"
	}
	if _, err := ParsePortSpec(spec); err != nil {
		return "", err
	}
	return spec, nil
}

func parseStrictPort(value, what string) (int, error) {
	if value == "" {
		return 0, fmt.Errorf("%s is required", what)
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("%s must be a number 1-65535 (got %q)", what, value)
		}
	}
	n, err := strconv.Atoi(value)
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("%s must be a number 1-65535 (got %q)", what, value)
	}
	return n, nil
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
		if strings.Contains(err.Error(), "guest port") {
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
	return m.submitShareForOS(runtime.GOOS)
}

func (m *sandboxTUIModel) submitShareForOS(goos string) (tea.Model, tea.Cmd) {
	targetName := m.shareSandbox.Value()
	target := m.sandboxNamed(targetName)
	if target == nil || target.State == tuiStarting {
		m.formError = "no eligible sandbox available"
		return m, m.focusShare(0)
	}
	tag := strings.TrimSpace(m.shareTag.Value())
	path := strings.TrimSpace(m.sharePath.Value())
	if tag == "" {
		m.formError = "tag is required"
		return m, m.focusShare(1)
	}
	// Validate with the designated single validator up front: an invalid
	// tag ("a=b", dots, over-long) would otherwise be misparsed downstream
	// or fail late as a raw background-command error.
	if err := shares.ValidateShareTag(tag); err != nil {
		m.formError = err.Error()
		return m, m.focusShare(1)
	}
	if path == "" {
		m.formError = "host path is required"
		return m, m.focusShare(2)
	}
	mountpoint := strings.TrimSpace(m.shareMount.Value())
	if mountpoint != "" && !strings.HasPrefix(mountpoint, "/") {
		// Container path: slash-absolute on every host OS (filepath.IsAbs
		// would reject "/data" on Windows).
		m.formError = "mount point must be an absolute path"
		return m, m.focusShare(3)
	}
	spec := tag + "=" + path
	defaultMount := shares.HubHostPath + "/" + tag
	customMount := mountpoint != "" && mountpoint != defaultMount
	if customMount {
		spec += "@" + mountpoint
	}
	if m.shareRO {
		spec += ",ro"
	}
	ownerSuffix, err := shareOwnerSuffix(m.shareOwner.Value())
	if err != nil {
		m.formError = err.Error()
		return m, m.focusShare(4)
	}
	spec += ownerSuffix
	requiresRestart := customMount || !shareCanApplyLiveOn(target, goos)
	if m.shareReplace {
		if row := m.selectedMount(); row != nil && row.Guest != "" && row.Guest != shares.HubHostPath+"/"+row.Tag {
			requiresRestart = true
		}
	}
	if requiresRestart {
		desiredMount := mountpoint
		if desiredMount == "" {
			desiredMount = defaultMount
		}
		m.dialog = tuiNoDialog
		m.busyAction = "share configure"
		m.busyName = targetName + "/" + tag
		return m, tea.Batch(
			configureSandboxShareCmd(targetName, tag, spec, desiredMount, m.shareReplace, target.State == tuiRunning),
			m.ensureAnimation(),
		)
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

func shareCanApplyLiveOn(target *tuiSandbox, goos string) bool {
	return target != nil && target.State == tuiRunning && goos != "darwin"
}

func shareOwnerSuffix(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" || value == "host" {
		return "", nil
	}
	uidText, gidText, ok := strings.Cut(value, ":")
	if !ok || uidText == "" || gidText == "" {
		return "", fmt.Errorf("guest owner must be host or UID:GID")
	}
	uid, err := strconv.ParseUint(uidText, 10, 32)
	if err != nil {
		return "", fmt.Errorf("invalid guest UID %q", uidText)
	}
	gid, err := strconv.ParseUint(gidText, 10, 32)
	if err != nil {
		return "", fmt.Errorf("invalid guest GID %q", gidText)
	}
	return fmt.Sprintf(",uid=%d,gid=%d", uid, gid), nil
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
	return m, tea.Batch(removeSandboxShareCmd(*row), m.ensureAnimation())
}

// Explicit @CTRPATH aliases are bind-mounted when the container is created.
// Removing their host export live therefore requires revocation; otherwise
// ShareManager correctly refuses the request and asks for --force. Stopped
// sandboxes have no live export, but using the same classification is harmless
// when the operation races a start and is delegated to the broker.
func shareRemovalNeedsForce(row tuiMountRow) bool {
	return row.Guest != "" && row.Guest != shares.HubHostPath+"/"+row.Tag
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
	m.shareOwner.Blur()
	m.shareSandbox.open = false
	m.portBind.Blur()
	m.portGuest.Blur()
	m.portSandbox.open = false
	m.policyPath.Blur()
	m.policySandbox.open = false
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
	m.shareMount.SetWidth(shareFieldWidth)
	m.shareOwner.SetWidth(shareFieldWidth)
	portWidth, _ := m.dialogSize(tuiPortPublishDialog)
	portFieldWidth := maxInt(12, portWidth-10)
	m.portBind.SetWidth(portFieldWidth)
	m.portGuest.SetWidth(portFieldWidth)
	policyWidth, _ := m.dialogSize(tuiNetworkPolicyDialog)
	m.policyPath.SetWidth(maxInt(12, policyWidth-10))
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
	m.spinner.Style = lipgloss.NewStyle().Foreground(theme.accent)
}

type tuiFormRowSpan struct {
	first int
	last  int
}

func (span tuiFormRowSpan) contains(row int) bool {
	return row >= span.first && row <= span.last
}

type tuiFormRowLayout struct {
	compact  []tuiFormRowSpan
	spacious []tuiFormRowSpan
}

var (
	createDialogRows = tuiFormRowLayout{
		compact:  []tuiFormRowSpan{{5, 7}, {9, 11}, {13, 14}, {15, 16}, {17, 19}, {20, 22}},
		spacious: []tuiFormRowSpan{{6, 9}, {11, 14}, {16, 17}, {19, 20}, {22, 23}, {25, 26}},
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
	lines := strings.Split(ansi.Strip(m.renderDialog(tuiThemeFor(m.dark))), "\n")
	for row := len(lines) - 1; row >= 0; row-- {
		byteOffset := strings.LastIndex(lines[row], label)
		if byteOffset < 0 {
			continue
		}
		start := maxInt(0, lipgloss.Width(lines[row][:byteOffset])-2)
		end := lipgloss.Width(lines[row][:byteOffset+len(label)]) + 2
		relX, relY := mouse.X-bounds.x, mouse.Y-bounds.y
		return relY == row && relX >= start && relX < end
	}
	return false
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
			rows := m.formControlRows(createDialogRows, 0)
			switch {
			case rows[0].contains(relY):
				return m, m.focusCreate(0)
			case rows[1].contains(relY):
				return m, m.focusCreate(1)
			case rows[2].contains(relY):
				m.createFocus = 2
				if m.createRuntime == "runsc" {
					m.createRuntime = "crun"
				} else {
					m.createRuntime = "runsc"
				}
				return m, nil
			case rows[3].contains(relY):
				m.createFocus = 3
				m.cycleCreateKernel(1)
				return m, nil
			case rows[4].contains(relY):
				m.setSliderFromMouse(&m.createCPUs, bounds, mouse.X, "CPU")
				return m, m.focusCreate(4)
			case rows[5].contains(relY):
				m.setSliderFromMouse(&m.createMemory, bounds, mouse.X, "MiB")
				return m, m.focusCreate(5)
			case m.dialogButtonHit(mouse, bounds, "Create"):
				m.createFocus = 6
				return m.submitCreate()
			}
		}
		if m.dialog == tuiEditDialog {
			relY := mouse.Y - bounds.y
			switch {
			case relY >= 6 && relY <= 8:
				m.setSliderFromMouse(&m.editCPUs, bounds, mouse.X, "CPU")
				return m, m.focusEdit(0)
			case relY >= 10 && relY <= 12:
				m.setSliderFromMouse(&m.editMemory, bounds, mouse.X, "MiB")
				return m, m.focusEdit(1)
			case m.dialogButtonHit(mouse, bounds, "Save"):
				m.editFocus = 2
				return m.submitEdit()
			}
		}
		if m.dialog == tuiShareAddDialog {
			relY := mouse.Y - bounds.y
			rows := m.formControlRows(shareDialogRows, m.shareSandbox.menuHeight())
			_, _, buttonLabel := m.shareDialogCopy()
			if m.shareSandbox.open && m.shareSandbox.chooseVisible(relY-rows[0].last-2) {
				return m, nil
			}
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
		}
		if m.dialog == tuiPortPublishDialog {
			relY := mouse.Y - bounds.y
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
		}
		if m.dialog == tuiNetworkPolicyDialog {
			relY := mouse.Y - bounds.y
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
