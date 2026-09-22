package dashboard

import "charm.land/bubbles/v2/textinput"

// Dialog-specific owners keep mutable form values separate from modal
// admission. Closing a modal releases focus and sensitive values through the
// existing form cleanup paths; these owners never control the dialog phase.
type editDialogState struct {
	editFocus         int
	editCPUs          resourceSlider
	editMemory        resourceSlider
	editIsolation     string
	editSSH           bool
	editDevContainers bool
}

type shareDialogState struct {
	shareFocus   int
	shareSandbox sandboxPicker
	shareTag     textinput.Model
	sharePath    textinput.Model
	shareMount   textinput.Model
	shareOwner   textinput.Model
	shareRO      bool
	shareReplace bool
}

type portDialogState struct {
	portFocus   int
	portSandbox sandboxPicker
	portBind    textinput.Model
	portGuest   textinput.Model
	portUDP     bool
}

type policyDialogState struct {
	policyFocus   int
	policySandbox sandboxPicker
	policyPath    textinput.Model
	policyLocal   bool
}

type ruleDialogState struct {
	ruleFocus    int
	ruleSandbox  sandboxPicker
	ruleTarget   textinput.Model
	rulePorts    textinput.Model
	ruleAction   string
	ruleProtocol string
}

type secretDialogState struct {
	secretFocus   int
	secretSandbox sandboxPicker
	secretName    textinput.Model
	secretValue   textinput.Model
}

type mcpDialogState struct {
	mcpFocus      int
	mcpSandbox    sandboxPicker
	mcpName       textinput.Model
	mcpURL        textinput.Model
	mcpAuthKind   string
	mcpAuthHeader textinput.Model
	mcpAuthRef    textinput.Model
	mcpAllow      textinput.Model
	mcpDeny       textinput.Model
	mcpRedact     textinput.Model
	mcpEditing    bool
	mcpFSFocus    int
	mcpFSRoot     textinput.Model
	mcpFSUser     textinput.Model
}

type imageDialogState struct {
	pullFocus     int
	pullRef       textinput.Model
	pullArch      string
	pullRemote    string
	loginFocus    int
	loginRemote   string
	loginRegistry textinput.Model
	loginUsername textinput.Model
	loginPassword textinput.Model
}

func (state *shareDialogState) releaseFocus() {
	state.shareTag.Blur()
	state.sharePath.Blur()
	state.shareOwner.Blur()
	state.shareSandbox.open = false
	state.shareReplace = false
}

func (state *portDialogState) releaseFocus() {
	state.portBind.Blur()
	state.portGuest.Blur()
	state.portSandbox.open = false
}

func (state *policyDialogState) releaseFocus() {
	state.policyPath.Blur()
	state.policySandbox.open = false
}

func (state *ruleDialogState) releaseFocus() {
	state.ruleTarget.Blur()
	state.rulePorts.Blur()
	state.ruleSandbox.open = false
}

func (state *secretDialogState) releaseFocus() {
	state.secretName.Blur()
	state.secretValue.Blur()
	state.secretValue.Reset()
	state.secretSandbox.open = false
}

func (state *mcpDialogState) releaseFocus() {
	state.mcpName.Blur()
	state.mcpURL.Blur()
	state.mcpAuthHeader.Blur()
	state.mcpAuthRef.Blur()
	state.mcpAllow.Blur()
	state.mcpDeny.Blur()
	state.mcpRedact.Blur()
	state.mcpFSRoot.Blur()
	state.mcpFSUser.Blur()
	state.mcpSandbox.open = false
	state.mcpEditing = false
}

func (state *imageDialogState) releaseFocus() {
	state.pullRef.Blur()
	state.loginRegistry.Blur()
	state.loginUsername.Blur()
	state.loginPassword.Blur()
	state.loginPassword.Reset()
	state.pullRemote = ""
	state.loginRemote = ""
}
