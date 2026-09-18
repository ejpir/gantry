// Package pagestate owns dashboard page transitions independently of the
// rendering and input frameworks.
package pagestate

// Page is an opaque page identifier supplied by the dashboard adapter.
type Page uint8

// Owner serializes the current page and the explicit navigation order.
type Owner struct {
	current Page
	limit   Page
	order   []Page
}

// New constructs an owner. Invalid entries in order are ignored; if initial
// is invalid, the zero page is selected.
func New(initial, limit Page, order []Page) Owner {
	if limit == 0 {
		return Owner{}
	}
	if initial >= limit {
		initial = 0
	}
	seen := make(map[Page]struct{}, len(order))
	valid := make([]Page, 0, len(order))
	for _, page := range order {
		if page >= limit {
			continue
		}
		if _, duplicate := seen[page]; duplicate {
			continue
		}
		seen[page] = struct{}{}
		valid = append(valid, page)
	}
	if len(valid) == 0 {
		return Owner{current: initial, limit: limit, order: []Page{initial}}
	}
	if _, exists := seen[initial]; !exists {
		valid = append([]Page{initial}, valid...)
	}
	return Owner{current: initial, limit: limit, order: valid}
}

// Current returns the selected page.
func (owner *Owner) Current() Page {
	if owner == nil {
		return 0
	}
	return owner.current
}

// Transition selects a valid page.
func (owner *Owner) Transition(next Page) bool {
	if owner == nil || owner.limit == 0 || next >= owner.limit {
		return false
	}
	owner.current = next
	return true
}

// Cycle computes a page relative to the current page without mutating state.
func (owner *Owner) Cycle(delta int) Page {
	if owner == nil || len(owner.order) == 0 {
		return 0
	}
	current := 0
	for index, page := range owner.order {
		if page == owner.current {
			current = index
			break
		}
	}
	next := (current + delta%len(owner.order) + len(owner.order)) % len(owner.order)
	return owner.order[next]
}
