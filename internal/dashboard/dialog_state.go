package dashboard

type tuiDialogPhase uint8

const (
	tuiDialogClosed tuiDialogPhase = iota
	tuiDialogOpen
)

// tuiDialogState is the sole owner of modal admission and common modal state.
// Dialog-specific form fields remain with their form owners, while every open,
// replacement, and close advances generation so delayed dialog work can be
// identified independently of a later modal of the same kind.
type tuiDialogState struct {
	dialog        tuiDialog
	dialogScroll  int
	confirmRemove bool
	formError     string
	generation    uint64
}

func (dialog tuiDialog) isOnboarding() bool {
	switch dialog {
	case tuiCreateLocationDialog, tuiRemoteProfilesDialog, tuiOrganizationLoginDialog,
		tuiOrganizationRemotesDialog, tuiRemoteAddDialog, tuiRemoteRemoveDialog:
		return true
	default:
		return false
	}
}

func (dialog tuiDialog) usesConfirmationKeys() bool {
	switch dialog {
	case tuiRemoveDialog, tuiShareRemoveDialog, tuiPortUnpublishDialog, tuiRuleRemoveDialog,
		tuiSecretRemoveDialog, tuiMCPRemoveDialog, tuiUpdateDialog, tuiImageRemoveDialog,
		tuiImagePruneDialog, tuiRegistryLogoutDialog:
		return true
	default:
		return false
	}
}

func (dialog tuiDialog) usesConfirmationMouse() bool {
	return dialog == tuiRemoteRemoveDialog || dialog.usesConfirmationKeys()
}

func (dialog tuiDialog) isReadOnly() bool {
	switch dialog {
	case tuiHelpDialog, tuiInfoDialog, tuiPacketDetailDialog, tuiAuditDetailDialog:
		return true
	default:
		return false
	}
}

func (state *tuiDialogState) phase() tuiDialogPhase {
	if state.dialog == tuiNoDialog {
		return tuiDialogClosed
	}
	return tuiDialogOpen
}

func (state *tuiDialogState) open(kind tuiDialog) bool {
	if kind == tuiNoDialog {
		return false
	}
	state.generation++
	state.dialog = kind
	state.dialogScroll = 0
	return true
}

func (state *tuiDialogState) openForm(kind tuiDialog) bool {
	if !state.open(kind) {
		return false
	}
	state.formError = ""
	return true
}

func (state *tuiDialogState) openConfirmation(kind tuiDialog) bool {
	if !state.open(kind) {
		return false
	}
	state.confirmRemove = false
	return true
}

func (state *tuiDialogState) dismiss() bool {
	if state.phase() == tuiDialogClosed {
		return false
	}
	state.generation++
	state.dialog = tuiNoDialog
	state.dialogScroll = 0
	return true
}

func (state *tuiDialogState) release() {
	state.dismiss()
	state.confirmRemove = false
	state.formError = ""
}
