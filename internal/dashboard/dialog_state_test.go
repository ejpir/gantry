package dashboard

import "testing"

func TestTUIDialogRoutingFamiliesPreserveRemoteRemovalSemantics(t *testing.T) {
	if !tuiRemoteRemoveDialog.isOnboarding() || tuiRemoteRemoveDialog.usesConfirmationKeys() || !tuiRemoteRemoveDialog.usesConfirmationMouse() {
		t.Fatal("remote removal must keep onboarding keys and confirmation mouse actions")
	}
	if !tuiHelpDialog.isReadOnly() || tuiCreateDialog.isReadOnly() {
		t.Fatal("read-only dialog classification is incorrect")
	}
}

func TestTUIDialogStateTransitions(t *testing.T) {
	var state tuiDialogState
	if state.phase() != tuiDialogClosed {
		t.Fatal("zero dialog state is not closed")
	}
	if state.open(tuiNoDialog) {
		t.Fatal("no-dialog was admitted as an open dialog")
	}
	if !state.openForm(tuiCreateDialog) {
		t.Fatal("create dialog did not open")
	}
	firstGeneration := state.generation
	state.formError = "invalid"
	state.dialogScroll = 4
	if !state.openConfirmation(tuiRemoveDialog) {
		t.Fatal("dialog replacement failed")
	}
	if state.phase() != tuiDialogOpen || state.dialog != tuiRemoveDialog || state.dialogScroll != 0 || state.confirmRemove {
		t.Fatalf("replacement state = %+v", state)
	}
	if state.formError != "invalid" {
		t.Fatal("confirmation replacement unexpectedly changed form-owned error")
	}
	if state.generation <= firstGeneration {
		t.Fatal("replacement did not advance generation")
	}
	if !state.dismiss() || state.phase() != tuiDialogClosed || state.dialogScroll != 0 {
		t.Fatalf("close state = %+v", state)
	}
	if state.dismiss() {
		t.Fatal("duplicate close was accepted")
	}
}

func TestTUIDialogStateReleaseClearsTransientStateOnce(t *testing.T) {
	state := tuiDialogState{dialog: tuiCreateDialog, dialogScroll: 7, confirmRemove: true, formError: "invalid", generation: 4}
	state.release()
	if state.phase() != tuiDialogClosed || state.dialogScroll != 0 || state.confirmRemove || state.formError != "" {
		t.Fatalf("released state = %+v", state)
	}
	generation := state.generation
	state.release()
	if state.generation != generation {
		t.Fatalf("duplicate release advanced generation from %d to %d", generation, state.generation)
	}
}

func TestTUIDialogStateFormOpenClearsOnlyCommonFormError(t *testing.T) {
	state := tuiDialogState{confirmRemove: true, formError: "old"}
	if !state.openForm(tuiEditDialog) {
		t.Fatal("edit dialog did not open")
	}
	if state.formError != "" {
		t.Fatalf("form error was retained: %q", state.formError)
	}
	if !state.confirmRemove {
		t.Fatal("form open changed confirmation-owned state")
	}
}
