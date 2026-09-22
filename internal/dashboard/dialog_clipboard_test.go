package dashboard

import (
	"testing"

	"github.com/ejpir/gantry/internal/sandbox/dashboardsvc"
)

func TestFocusedDialogCopyPreservesFormSemantics(t *testing.T) {
	m := newSandboxTUIModel(dashboardsvc.NewDashboardService())

	m.dialog, m.createFocus = tuiCreateDialog, 3
	assertDialogCopy(t, m, "auto", "kernel")

	m.dialog, m.shareFocus, m.shareRO = tuiShareAddDialog, 5, true
	assertDialogCopy(t, m, "read-only", "share mode")
	m.shareRO = false
	assertDialogCopy(t, m, "read-write", "share mode")

	m.dialog, m.portFocus, m.portUDP = tuiPortPublishDialog, 3, true
	assertDialogCopy(t, m, "udp", "protocol")

	m.dialog, m.policyFocus, m.policyLocal = tuiNetworkPolicyDialog, 2, true
	assertDialogCopy(t, m, "allowed", "local network override")

	m.dialog, m.ruleFocus, m.ruleProtocol = tuiRuleAddDialog, 2, "dns"
	m.ruleTarget.SetValue("example.test")
	assertDialogCopy(t, m, "example.test", "domain")

	m.dialog, m.onboardFocus = tuiRemoteAddDialog, 2
	assertDialogCopy(t, m, "", "manager token is write-only")
}

func assertDialogCopy(t *testing.T, model sandboxTUIModel, wantValue, wantLabel string) {
	t.Helper()
	value, label := model.dialogCopyValue()
	if value != wantValue || label != wantLabel {
		t.Fatalf("dialog %d copy = (%q, %q), want (%q, %q)", model.dialog, value, label, wantValue, wantLabel)
	}
}

func TestDialogFocusLineSearchDirection(t *testing.T) {
	lines := []string{"title", "padding", "Name", "field", "Name", "button"}
	if got := dialogFocusLine(lines, "Name", false); got != 2 {
		t.Fatalf("forward focus line = %d, want 2", got)
	}
	if got := dialogFocusLine(lines, "Name", true); got != 4 {
		t.Fatalf("reverse focus line = %d, want 4", got)
	}
	if got := dialogFocusLine(lines, "missing", false); got != -1 {
		t.Fatalf("missing focus line = %d, want -1", got)
	}
}
