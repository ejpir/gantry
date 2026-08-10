package workerconf

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func probeTaskLimit(expected uint64) PropertyResult {
	if expected == 0 {
		return PropertyResult{Property: PropTaskLimit, State: StateDisabled}
	}
	if os.Getpid() != 1 {
		return PropertyResult{
			Property: PropTaskLimit,
			State:    StateUnenforced,
			Detail:   "worker is not PID 1 in a dedicated namespace",
		}
	}
	var limit unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NPROC, &limit); err != nil {
		return PropertyResult{Property: PropTaskLimit, State: StateIndeterminate, Detail: errString(err)}
	}
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	data := [2]unix.CapUserData{}
	if err := unix.Capget(&header, &data[0]); err != nil {
		return PropertyResult{Property: PropTaskLimit, State: StateIndeterminate, Detail: errString(err)}
	}
	for _, set := range data {
		if set.Effective != 0 || set.Permitted != 0 {
			return PropertyResult{
				Property: PropTaskLimit,
				State:    StateUnenforced,
				Detail:   "effective/permitted capabilities can bypass RLIMIT_NPROC",
			}
		}
	}
	if limit.Cur > expected || limit.Max > expected {
		return PropertyResult{
			Property: PropTaskLimit,
			State:    StateUnenforced,
			Detail:   fmt.Sprintf("RLIMIT_NPROC=%d/%d, want <=%d", limit.Cur, limit.Max, expected),
		}
	}
	return PropertyResult{
		Property: PropTaskLimit,
		State:    StateEnforced,
		Detail:   fmt.Sprintf("RLIMIT_NPROC=%d; capabilities empty", limit.Cur),
	}
}
