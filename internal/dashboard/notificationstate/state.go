// Package notificationstate owns generation-scoped dashboard notifications.
package notificationstate

// Phase is the notification visibility lifecycle.
type Phase uint8

const (
	Idle Phase = iota
	Visible
)

// Kind is an opaque notification classification supplied by the dashboard.
type Kind uint8

// Notification is an immutable snapshot of the visible notification.
type Notification struct {
	Kind       Kind
	Title      string
	Body       string
	Generation uint64
}

// Owner owns replacement, expiry, and dismissal generations.
type Owner struct {
	current    Notification
	generation uint64
	visible    bool
}

// Phase reports whether a notification is visible.
func (owner *Owner) Phase() Phase {
	if owner == nil || !owner.visible {
		return Idle
	}
	return Visible
}

// Publish replaces the current notification and returns its generation.
func (owner *Owner) Publish(kind Kind, title, body string) uint64 {
	if owner == nil {
		return 0
	}
	owner.generation++
	owner.current = Notification{
		Kind:       kind,
		Title:      title,
		Body:       body,
		Generation: owner.generation,
	}
	owner.visible = true
	return owner.generation
}

// Current returns an immutable snapshot of the visible notification.
func (owner *Owner) Current() (Notification, bool) {
	if owner == nil || !owner.visible {
		return Notification{}, false
	}
	return owner.current, true
}

// Expire clears only the notification matching generation.
func (owner *Owner) Expire(generation uint64) bool {
	if owner == nil || !owner.visible || owner.current.Generation != generation {
		return false
	}
	owner.current = Notification{}
	owner.visible = false
	return true
}

// Dismiss clears the current notification.
func (owner *Owner) Dismiss() bool {
	if owner == nil || !owner.visible {
		return false
	}
	owner.current = Notification{}
	owner.visible = false
	return true
}
