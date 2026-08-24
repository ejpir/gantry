package workerconf

import (
	"fmt"
	"sort"
	"unsafe"

	"golang.org/x/sys/windows"
)

const tokenIsAppContainer = 29
const tokenCapabilitiesClass = 30

var isProcessInJobProc = windows.NewLazySystemDLL("kernel32.dll").NewProc("IsProcessInJob")

var requiredNetworkCapabilitySIDs = []string{
	"S-1-15-3-1", // internetClient
	"S-1-15-3-2", // internetClientServer
	"S-1-15-3-3", // privateNetworkClientServer
}

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
	var capabilities []string
	var capabilitiesErr error
	if appContainerErr == nil && appContainer {
		capabilities, capabilitiesErr = tokenCapabilities(token)
	}
	hasCapabilities := len(capabilities) != 0
	restricted, tokenErr := token.IsRestricted()
	inJob, jobErr := currentProcessInJob()
	rep.Applied = appContainer || restricted || inJob
	if appContainer {
		switch {
		case capabilitiesErr != nil:
			rep.Notes = append(rep.Notes, "AppContainer token active; capabilities unreadable")
		case hasCapabilities:
			rep.Notes = append(rep.Notes, fmt.Sprintf("network-capable AppContainer token active (%v)", capabilities))
		default:
			rep.Notes = append(rep.Notes, "zero-capability AppContainer token active")
		}
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
	if appContainerErr != nil || capabilitiesErr != nil || tokenErr != nil || jobErr != nil {
		return &rep, fmt.Errorf("inspect Windows confinement: appcontainer=%v capabilities=%v token=%v job=%v",
			appContainerErr, capabilitiesErr, tokenErr, jobErr)
	}
	if !rep.Applied {
		return &rep, fmt.Errorf("windows worker AppContainer/token/job confinement not installed")
	}
	if appContainer && spec.NoNetwork && hasCapabilities {
		return &rep, fmt.Errorf("windows no-network worker received AppContainer capabilities")
	}
	if appContainer && !spec.NoNetwork {
		if !sameStrings(capabilities, requiredNetworkCapabilitySIDs) {
			return &rep, fmt.Errorf("windows network worker capability set %v does not match required %v",
				capabilities, requiredNetworkCapabilitySIDs)
		}
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
	capabilities, err := tokenCapabilities(token)
	return len(capabilities) != 0, err
}

func tokenCapabilities(token windows.Token) ([]string, error) {
	var size uint32
	err := windows.GetTokenInformation(token, tokenCapabilitiesClass, nil, 0, &size)
	if err != windows.ERROR_INSUFFICIENT_BUFFER {
		return nil, err
	}
	buffer := make([]byte, size)
	if err := windows.GetTokenInformation(token, tokenCapabilitiesClass,
		&buffer[0], size, &size); err != nil {
		return nil, err
	}
	groups := (*windows.Tokengroups)(unsafe.Pointer(&buffer[0]))
	capabilities := make([]string, 0, groups.GroupCount)
	for _, group := range groups.AllGroups() {
		if group.Sid == nil {
			return nil, fmt.Errorf("windows token contains a nil capability SID")
		}
		capabilities = append(capabilities, group.Sid.String())
	}
	sort.Strings(capabilities)
	return capabilities, nil
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	rightSorted := append([]string(nil), right...)
	sort.Strings(rightSorted)
	for index := range left {
		if left[index] != rightSorted[index] {
			return false
		}
	}
	return true
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
