package workerconf

import (
	"errors"
	"syscall"

	"golang.org/x/sys/unix"
)

// probeProcEnum asks Darwin for the ordinary KERN_PROC all-process list. The
// exact sysctl Seatbelt allowlist must reject it, while an unconfined process
// supplies at least itself as the positive control.
func probeProcEnum() PropertyResult {
	processes, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err == nil {
		if len(processes) == 0 {
			return PropertyResult{Property: PropProcEnum, State: StateIndeterminate, Detail: "KERN_PROC returned an empty list"}
		}
		return PropertyResult{Property: PropProcEnum, State: StateUnenforced, Detail: "KERN_PROC listed host processes"}
	}
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
		return PropertyResult{Property: PropProcEnum, State: StateEnforced, Detail: errString(err)}
	}
	return PropertyResult{Property: PropProcEnum, State: StateIndeterminate, Detail: errString(err)}
}
