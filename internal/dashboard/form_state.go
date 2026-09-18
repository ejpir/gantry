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
	loginFocus    int
	loginRegistry textinput.Model
	loginUsername textinput.Model
	loginPassword textinput.Model
}
