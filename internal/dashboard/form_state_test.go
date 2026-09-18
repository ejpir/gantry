package dashboard

import (
	"testing"

	"charm.land/bubbles/v2/textinput"
)

func TestDialogFormOwnersReleaseSensitiveAndFocusState(t *testing.T) {
	shareTag := textinput.New()
	shareTag.SetValue("source")
	share := shareDialogState{shareTag: shareTag, shareReplace: true, shareSandbox: sandboxPicker{open: true}}
	share.releaseFocus()
	if share.shareReplace || share.shareSandbox.open || share.shareTag.Value() != "source" {
		t.Fatalf("released share state = %+v tag %q", share, share.shareTag.Value())
	}

	secretValue := textinput.New()
	secretValue.SetValue("secret-value")
	secretState := secretDialogState{secretValue: secretValue, secretSandbox: sandboxPicker{open: true}}
	secretState.releaseFocus()
	if secretState.secretSandbox.open || secretState.secretValue.Value() != "" {
		t.Fatalf("released secret state retained value or picker: value %q open %v", secretState.secretValue.Value(), secretState.secretSandbox.open)
	}

	password := textinput.New()
	password.SetValue("registry-token")
	image := imageDialogState{loginPassword: password}
	image.releaseFocus()
	if image.loginPassword.Value() != "" {
		t.Fatalf("released image state retained password %q", image.loginPassword.Value())
	}

	mcp := mcpDialogState{mcpEditing: true, mcpSandbox: sandboxPicker{open: true}}
	mcp.releaseFocus()
	if mcp.mcpEditing || mcp.mcpSandbox.open {
		t.Fatalf("released MCP state = editing %v open %v", mcp.mcpEditing, mcp.mcpSandbox.open)
	}
}
