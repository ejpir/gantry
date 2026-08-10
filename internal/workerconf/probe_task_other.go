//go:build !linux

package workerconf

import "runtime"

func probeTaskLimit(expected uint64) PropertyResult {
	if expected == 0 {
		return PropertyResult{Property: PropTaskLimit, State: StateDisabled}
	}
	return PropertyResult{
		Property: PropTaskLimit,
		State:    StateUnavailable,
		Detail:   "per-worker task limits unavailable on " + runtime.GOOS,
	}
}
