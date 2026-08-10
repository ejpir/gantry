package workerconf

import "os"

// probeProcEnum proves that the private mount namespace exposes no procfs.
func probeProcEnum() PropertyResult {
	f, err := os.Open("/proc")
	if err != nil {
		return PropertyResult{Property: PropProcEnum, State: StateEnforced, Detail: errString(err)}
	}
	_ = f.Close()
	return PropertyResult{Property: PropProcEnum, State: StateUnenforced, Detail: "/proc readable"}
}
