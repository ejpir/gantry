package workerconf

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

const tokenIsAppContainer = 29
const tokenCapabilities = 30

var isProcessInJobProc = windows.NewLazySystemDLL("kernel32.dll").NewProc("IsProcessInJob")

// Apply records the parent-installed Windows controls. AppContainer/restricted
// tokens and Job membership must be established by CreateProcess/AssignProcess
// in the trusted supervisor; a child cannot safely retrofit those boundaries
// onto every thread in its own process.
func Apply(spec Spec) (*Report, error) {
	if !validProfile(spec.Profile) {
		return nil, fmt.Errorf("workerconf: invalid syscall profile %d", spec.Profile)
	}
	rep := DisabledReport("windows", "")
	token := windows.GetCurrentProcessToken()
	appContainer, appContainerErr := tokenIsAppContainerEnabled(token)
	restricted, tokenErr := token.IsRestricted()
	inJob, jobErr := currentProcessInJob()
	rep.Applied = appContainer || restricted || inJob
	if appContainer {
		rep.Notes = append(rep.Notes, "zero-capability AppContainer token active")
	} else if appContainerErr == nil {
		rep.Notes = append(rep.Notes, "AppContainer token absent")
	}
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
	if appContainerErr != nil || tokenErr != nil || jobErr != nil {
		return &rep, fmt.Errorf("inspect Windows confinement: appcontainer=%v token=%v job=%v",
			appContainerErr, tokenErr, jobErr)
	}
	if !rep.Applied {
		return &rep, fmt.Errorf("windows worker AppContainer/token/job confinement not installed")
	}
	return &rep, nil
}

func tokenIsAppContainerEnabled(token windows.Token) (bool, error) {
	var enabled uint32
	var size uint32
	err := windows.GetTokenInformation(token, tokenIsAppContainer,
		(*byte)(unsafe.Pointer(&enabled)), uint32(unsafe.Sizeof(enabled)), &size)
	if err != nil {
		return false, err
	}
	return enabled != 0, nil
}

func tokenHasCapabilities(token windows.Token) (bool, error) {
	var size uint32
	err := windows.GetTokenInformation(token, tokenCapabilities, nil, 0, &size)
	if err != windows.ERROR_INSUFFICIENT_BUFFER {
		return false, err
	}
	buffer := make([]byte, size)
	if err := windows.GetTokenInformation(token, tokenCapabilities,
		&buffer[0], size, &size); err != nil {
		return false, err
	}
	groups := (*windows.Tokengroups)(unsafe.Pointer(&buffer[0]))
	return groups.GroupCount != 0, nil
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
