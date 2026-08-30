package dashboard

import (
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/ejpir/gantry/internal/sandbox/dashboardsvc"
)

func TestClassifyFormKey(t *testing.T) {
	tests := []struct {
		name       string
		key        string
		focus      int
		last       int
		toggle     int
		wantAction tuiFormKeyAction
		wantFocus  int
	}{
		{name: "next wraps", key: "tab", focus: 6, last: 6, toggle: 5, wantAction: tuiFormKeyFocus, wantFocus: 0},
		{name: "previous wraps", key: "shift+tab", focus: 0, last: 6, toggle: 5, wantAction: tuiFormKeyFocus, wantFocus: 6},
		{name: "enter advances", key: "enter", focus: 2, last: 6, toggle: 5, wantAction: tuiFormKeyFocus, wantFocus: 3},
		{name: "enter submits", key: "enter", focus: 6, last: 6, toggle: 5, wantAction: tuiFormKeySubmit, wantFocus: 6},
		{name: "control enter submits", key: "ctrl+enter", focus: 1, last: 6, toggle: 5, wantAction: tuiFormKeySubmit, wantFocus: 1},
		{name: "choice toggles", key: "left", focus: 5, last: 6, toggle: 5, wantAction: tuiFormKeyToggle, wantFocus: 5},
		{name: "text receives arrow", key: "left", focus: 1, last: 6, toggle: 5, wantAction: tuiFormKeyInput, wantFocus: 1},
		{name: "escape closes", key: "esc", focus: 1, last: 6, toggle: 5, wantAction: tuiFormKeyClose, wantFocus: 1},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			action, focus := classifyFormKey(test.key, test.focus, test.last, test.toggle)
			if action != test.wantAction || focus != test.wantFocus {
				t.Fatalf("classifyFormKey(%q, %d, %d, %d) = (%d, %d), want (%d, %d)",
					test.key, test.focus, test.last, test.toggle, action, focus, test.wantAction, test.wantFocus)
			}
		})
	}
}

func TestBusyKeyDispatchOnlyAllowsNavigation(t *testing.T) {
	m := newSandboxTUIModel(dashboardsvc.NewDashboardService())
	m.loading = false
	m.busyAction = "start"

	_, _ = m.updateKey(tea.KeyPressMsg{Code: '2'})
	if m.page != tuiTrafficPage {
		t.Fatalf("page after 2 = %d, want traffic", m.page)
	}
	_, _ = m.updateKey(tea.KeyPressMsg{Code: tea.KeyTab})
	if m.page != tuiRulesPage {
		t.Fatalf("page after tab = %d, want rules", m.page)
	}
	_, _ = m.updateKey(tea.KeyPressMsg{Code: 'n'})
	if m.dialog != tuiNoDialog {
		t.Fatalf("busy n opened dialog %d", m.dialog)
	}
	_, cmd := m.updateKey(tea.KeyPressMsg{Code: 'c', Mod: tea.ModCtrl})
	if cmd == nil {
		t.Fatal("busy ctrl+c returned no command")
	}
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Fatalf("busy ctrl+c returned %T, want tea.QuitMsg", cmd())
	}
}

func TestConfirmationDialogMouseDispatch(t *testing.T) {
	tests := []struct {
		name       string
		dialog     tuiDialog
		configure  func(*sandboxTUIModel)
		wantAction string
	}{
		{
			name:   "sandbox",
			dialog: tuiRemoveDialog,
			configure: func(m *sandboxTUIModel) {
				m.sandboxes = []tuiSandbox{{Name: "dev", State: tuiStopped}}
			},
			wantAction: "delete",
		},
		{
			name:   "share",
			dialog: tuiShareRemoveDialog,
			configure: func(m *sandboxTUIModel) {
				m.mounts = []tuiMountRow{{Sandbox: "dev", Tag: "code"}}
			},
			wantAction: "share remove",
		},
		{
			name:   "port",
			dialog: tuiPortUnpublishDialog,
			configure: func(m *sandboxTUIModel) {
				m.ports = []tuiPortRow{{Sandbox: "dev", Bind: "127.0.0.1:8080", Guest: 80, Proto: "tcp"}}
			},
			wantAction: "port unpublish",
		},
		{
			name:   "image remove",
			dialog: tuiImageRemoveDialog,
			configure: func(m *sandboxTUIModel) {
				m.images = []tuiImageRow{{Ref: "alpine:latest", Digest: "sha256:abc", Arch: "arm64"}}
			},
			wantAction: "image remove",
		},
		{
			name:   "image prune",
			dialog: tuiImagePruneDialog,
			configure: func(m *sandboxTUIModel) {
				m.images = []tuiImageRow{{Ref: "alpine:latest", Digest: "sha256:abc", Arch: "arm64"}}
			},
			wantAction: "image prune",
		},
		{
			name:   "registry logout",
			dialog: tuiRegistryLogoutDialog,
			configure: func(m *sandboxTUIModel) {
				m.registries = []tuiRegistryRow{{Registry: "ghcr.io", Username: "octocat", HasSecret: true}}
			},
			wantAction: "registry logout",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			m := newSandboxTUIModel(dashboardsvc.NewDashboardService())
			m.loading = false
			m.width, m.height = 100, 30
			test.configure(&m)
			m.dialog = test.dialog
			bounds := m.dialogBounds(test.dialog)
			cancel, ok := m.dialogButtonRect(bounds, "Cancel")
			if !ok {
				t.Fatal("rendered cancel button not found")
			}
			cancelled, cancelCmd := m.updateMouseClick(tea.Mouse{X: cancel.x + cancel.w/2, Y: cancel.y, Button: tea.MouseLeft})
			if got := cancelled.(*sandboxTUIModel); got.dialog != tuiNoDialog || cancelCmd != nil {
				t.Fatalf("cancel click left dialog=%d cmd=%v", got.dialog, cancelCmd)
			}

			m.dialog = test.dialog
			bounds = m.dialogBounds(test.dialog)
			button, ok := m.dialogButtonRect(bounds, m.confirmationActionLabel())
			if !ok {
				t.Fatal("rendered confirmation button not found")
			}

			model, cmd := m.updateMouseClick(tea.Mouse{
				X:      button.x + button.w/2,
				Y:      button.y,
				Button: tea.MouseLeft,
			})
			got := model.(*sandboxTUIModel)
			if got.busyAction != test.wantAction || got.dialog != tuiNoDialog || cmd == nil {
				t.Fatalf("confirmation result: action=%q dialog=%d cmd=%v, want action=%q closed dialog and command",
					got.busyAction, got.dialog, cmd, test.wantAction)
			}
		})
	}
}
