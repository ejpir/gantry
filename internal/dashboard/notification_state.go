package dashboard

type tuiNotificationPhase uint8

const (
	tuiNotificationIdle tuiNotificationPhase = iota
	tuiNotificationVisible
)

// tuiNotificationState owns toast replacement and expiry generations. An
// expiry from an older toast cannot clear the currently visible notification.
type tuiNotificationState struct {
	toast    *tuiToast
	toastGen uint64
}

func (state *tuiNotificationState) phase() tuiNotificationPhase {
	if state.toast == nil {
		return tuiNotificationIdle
	}
	return tuiNotificationVisible
}

func (state *tuiNotificationState) publish(kind tuiToastKind, title, body string) uint64 {
	state.toastGen++
	state.toast = &tuiToast{kind: kind, title: title, body: body, gen: state.toastGen}
	return state.toastGen
}

func (state *tuiNotificationState) expire(generation uint64) bool {
	if state.toast == nil || state.toast.gen != generation {
		return false
	}
	state.toast = nil
	return true
}

func (state *tuiNotificationState) dismiss() bool {
	if state.toast == nil {
		return false
	}
	state.toast = nil
	return true
}
