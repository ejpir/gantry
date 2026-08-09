//go:build !darwin

package workerconf

import "runtime"

func probeProcSignal(noProcX bool) PropertyResult {
	if !noProcX {
		return PropertyResult{Property: PropProcSignal, State: StateDisabled}
	}
	return PropertyResult{
		Property: PropProcSignal, State: StateUnavailable,
		Detail: "Seatbelt signal probe unavailable on " + runtime.GOOS,
	}
}
