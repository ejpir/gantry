//go:build !linux && !darwin

package workerconf

import "runtime"

func probeProcEnum() PropertyResult {
	return PropertyResult{Property: PropProcEnum, State: StateUnavailable, Detail: "no process-enumeration probe on " + runtime.GOOS}
}
