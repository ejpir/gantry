package workerconf

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var isProcessInJobProc = windows.NewLazySystemDLL("kernel32.dll").NewProc("IsProcessInJob")

// Apply records the parent-installed Windows controls. Restricted primary
// tokens and job membership must be established by CreateProcess/AssignProcess
// in the trusted supervisor; a child cannot safely retrofit either boundary
// onto every thread in its own process.
func Apply(Spec) (*Report, error) {
	rep := DisabledReport("windows", "")
	restricted, tokenErr := windows.GetCurrentProcessToken().IsRestricted()
	inJob, jobErr := currentProcessInJob()
	rep.Applied = restricted || inJob
	if restricted {
		rep.Notes = append(rep.Notes, "restricted primary token active")
	} else if tokenErr == nil {
		rep.Notes = append(rep.Notes, "restricted primary token absent")
	}
	if inJob {
		rep.Notes = append(rep.Notes, "worker job active (kill-on-close, one-process limit)")
	} else if jobErr == nil {
		rep.Notes = append(rep.Notes, "worker job absent")
	}
	if tokenErr != nil || jobErr != nil {
		return &rep, fmt.Errorf("inspect Windows confinement: token=%v job=%v", tokenErr, jobErr)
	}
	if !rep.Applied {
		return &rep, fmt.Errorf("Windows worker token/job confinement not installed")
	}
	return &rep, nil
}

func currentProcessInJob() (bool, error) {
	var inJob int32
	r1, _, callErr := isProcessInJobProc.Call(
		uintptr(windows.CurrentProcess()), 0, uintptr(unsafe.Pointer(&inJob)))
	if r1 == 0 {
		return false, callErr
	}
	return inJob != 0, nil
}
