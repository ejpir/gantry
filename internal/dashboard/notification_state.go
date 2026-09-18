package dashboard

import "github.com/ejpir/gantry/internal/dashboard/notificationstate"

type tuiNotificationPhase uint8

const (
	tuiNotificationIdle tuiNotificationPhase = iota
	tuiNotificationVisible
)

// tuiNotificationState adapts generation-scoped notification ownership to the
// dashboard's rendering type. toast is a read-only projection for renderers.
type tuiNotificationState struct {
	owner notificationstate.Owner
	toast *tuiToast
}

func (state *tuiNotificationState) phase() tuiNotificationPhase {
	if state == nil || state.owner.Phase() == notificationstate.Idle {
		return tuiNotificationIdle
	}
	return tuiNotificationVisible
}

func (state *tuiNotificationState) publish(kind tuiToastKind, title, body string) uint64 {
	generation := state.owner.Publish(notificationstate.Kind(kind), title, body)
	state.syncProjection()
	return generation
}

func (state *tuiNotificationState) expire(generation uint64) bool {
	if !state.owner.Expire(generation) {
		return false
	}
	state.syncProjection()
	return true
}

func (state *tuiNotificationState) dismiss() bool {
	if !state.owner.Dismiss() {
		return false
	}
	state.syncProjection()
	return true
}

func (state *tuiNotificationState) syncProjection() {
	notification, visible := state.owner.Current()
	if !visible {
		state.toast = nil
		return
	}
	state.toast = &tuiToast{
		kind:  tuiToastKind(notification.Kind),
		title: notification.Title,
		body:  notification.Body,
		gen:   notification.Generation,
	}
}
