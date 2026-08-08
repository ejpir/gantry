package workerconf

import "fmt"

// Apply is the Windows enforcer placeholder (M4: job object +
// restricted token, applied parent-side at spawn — see
// docs/worker-confinement.md). The Windows _vmm-worker process split
// itself (M3) does not exist yet either.
func Apply(Spec) (*Report, error) {
	rep := DisabledReport("windows", "")
	rep.Notes = append(rep.Notes, "job-object/token enforcer not implemented (M4)")
	return &rep, fmt.Errorf("workerconf: windows enforcer not implemented (M4)")
}
