package workerconf

import "fmt"

// Apply is the macOS enforcer placeholder (M2: Seatbelt via purego —
// see docs/worker-confinement.md). Until then every property reports
// unavailable; auto-mode boots proceed unconfined and required-mode
// callers refuse via Report.Failed.
func Apply(Spec) (*Report, error) {
	rep := DisabledReport("darwin", "")
	rep.Notes = append(rep.Notes, "seatbelt enforcer not implemented (M2)")
	return &rep, fmt.Errorf("workerconf: darwin enforcer not implemented (M2)")
}
