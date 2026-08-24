package worker

import (
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const procThreadAttributeSecurityCapabilities = 0x00020009

type windowsSecurityCapabilities struct {
	appContainerSID *windows.SID
	capabilities    *windows.SIDAndAttributes
	capabilityCount uint32
	reserved        uint32
}

type windowsCreatedProcess struct {
	process       *os.Process
	processHandle windows.Handle
	threadHandle  windows.Handle
}

// createWindowsProcessSuspended is the AppContainer-capable equivalent of
// os.StartProcess. The standard library builds an exact inherited-handle list,
// but does not expose PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES. Keeping the
// process suspended also closes the historical race between CreateProcess and
// AssignProcessToJobObject.
func createWindowsProcessSuspended(exe string, argv, env []string, files []*os.File,
	handles []syscall.Handle, profile *windowsAppContainerProfile) (*windowsCreatedProcess, error) {
	if len(files) != 3 {
		return nil, fmt.Errorf("windows worker requires exactly three standard handles")
	}

	applicationName, err := windows.UTF16FromString(exe)
	if err != nil {
		return nil, fmt.Errorf("encode worker executable: %w", err)
	}
	commandLine, err := windows.UTF16FromString(windows.ComposeCommandLine(argv))
	if err != nil {
		return nil, fmt.Errorf("encode worker command line: %w", err)
	}
	environment, err := windowsEnvironmentBlock(env)
	if err != nil {
		return nil, err
	}

	currentProcess := windows.CurrentProcess()
	standardHandles := make([]windows.Handle, len(files))
	for index, file := range files {
		if file == nil {
			closeWindowsHandles(standardHandles)
			return nil, fmt.Errorf("standard handle %d is nil", index)
		}
		if err := windows.DuplicateHandle(currentProcess, windows.Handle(file.Fd()), currentProcess,
			&standardHandles[index], 0, true, windows.DUPLICATE_SAME_ACCESS); err != nil {
			closeWindowsHandles(standardHandles)
			return nil, fmt.Errorf("duplicate standard handle %d: %w", index, err)
		}
	}
	defer closeWindowsHandles(standardHandles)

	inherited := make([]windows.Handle, 0, len(standardHandles)+len(handles))
	inherited = append(inherited, standardHandles...)
	for _, handle := range handles {
		if handle != 0 {
			inherited = append(inherited, windows.Handle(handle))
		}
	}
	if len(inherited) == 0 {
		return nil, fmt.Errorf("windows worker inherited-handle list is empty")
	}

	attributeCount := uint32(1)
	if profile != nil {
		attributeCount++
	}
	attributes, err := windows.NewProcThreadAttributeList(attributeCount)
	if err != nil {
		return nil, fmt.Errorf("create process attribute list: %w", err)
	}
	defer attributes.Delete()
	if err := attributes.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
		unsafe.Pointer(&inherited[0]), uintptr(len(inherited))*unsafe.Sizeof(inherited[0])); err != nil {
		return nil, fmt.Errorf("set inherited-handle list: %w", err)
	}

	securityCapabilities := windowsSecurityCapabilities{}
	if profile != nil {
		securityCapabilities.appContainerSID = profile.sid
		securityCapabilities.capabilityCount = uint32(len(profile.capabilities))
		if len(profile.capabilities) != 0 {
			securityCapabilities.capabilities = &profile.capabilities[0]
		}
		if err := attributes.Update(procThreadAttributeSecurityCapabilities,
			unsafe.Pointer(&securityCapabilities), unsafe.Sizeof(securityCapabilities)); err != nil {
			return nil, fmt.Errorf("set AppContainer security capabilities: %w", err)
		}
	}

	startupInfo := windows.StartupInfoEx{
		StartupInfo: windows.StartupInfo{
			Cb:        uint32(unsafe.Sizeof(windows.StartupInfoEx{})),
			Flags:     windows.STARTF_USESTDHANDLES,
			StdInput:  standardHandles[0],
			StdOutput: standardHandles[1],
			StdErr:    standardHandles[2],
		},
		ProcThreadAttributeList: attributes.List(),
	}
	var processInfo windows.ProcessInformation
	flags := uint32(windows.CREATE_NO_WINDOW | windows.CREATE_SUSPENDED |
		windows.CREATE_UNICODE_ENVIRONMENT | windows.EXTENDED_STARTUPINFO_PRESENT)
	if err := windows.CreateProcess(
		&applicationName[0], &commandLine[0], nil, nil, true, flags,
		&environment[0], nil, &startupInfo.StartupInfo, &processInfo); err != nil {
		return nil, err
	}

	process, err := os.FindProcess(int(processInfo.ProcessId))
	if err != nil {
		_ = windows.TerminateProcess(processInfo.Process, 1)
		_, _ = windows.WaitForSingleObject(processInfo.Process, windows.INFINITE)
		_ = windows.CloseHandle(processInfo.Thread)
		_ = windows.CloseHandle(processInfo.Process)
		return nil, fmt.Errorf("open created worker process: %w", err)
	}
	runtime.KeepAlive(inherited)
	runtime.KeepAlive(securityCapabilities)
	runtime.KeepAlive(profile)
	return &windowsCreatedProcess{
		process: process, processHandle: processInfo.Process, threadHandle: processInfo.Thread,
	}, nil
}

func (created *windowsCreatedProcess) resume() error {
	if created == nil || created.threadHandle == 0 {
		return fmt.Errorf("resume Windows worker: missing primary thread")
	}
	if _, err := windows.ResumeThread(created.threadHandle); err != nil {
		return fmt.Errorf("resume Windows worker: %w", err)
	}
	return nil
}

func (created *windowsCreatedProcess) abort() {
	if created == nil {
		return
	}
	if created.processHandle != 0 {
		_ = windows.TerminateProcess(created.processHandle, 1)
		_, _ = windows.WaitForSingleObject(created.processHandle, windows.INFINITE)
	}
	created.closeCreationHandles()
	if created.process != nil {
		_ = created.process.Release()
		created.process = nil
	}
}

func (created *windowsCreatedProcess) closeCreationHandles() {
	if created == nil {
		return
	}
	if created.threadHandle != 0 {
		_ = windows.CloseHandle(created.threadHandle)
		created.threadHandle = 0
	}
	if created.processHandle != 0 {
		_ = windows.CloseHandle(created.processHandle)
		created.processHandle = 0
	}
}

func closeWindowsHandles(handles []windows.Handle) {
	for _, handle := range handles {
		if handle != 0 {
			_ = windows.CloseHandle(handle)
		}
	}
}

func windowsEnvironmentBlock(environment []string) ([]uint16, error) {
	ordered := append([]string(nil), environment...)
	sort.SliceStable(ordered, func(i, j int) bool {
		return strings.ToUpper(ordered[i]) < strings.ToUpper(ordered[j])
	})
	block := make([]uint16, 0, 64)
	for index, entry := range ordered {
		encoded, err := windows.UTF16FromString(entry)
		if err != nil {
			return nil, fmt.Errorf("encode environment entry %d: %w", index, err)
		}
		block = append(block, encoded...)
	}
	// UTF16FromString includes one terminator per entry; CreateProcess requires
	// one additional terminator after the complete environment block.
	block = append(block, 0)
	if len(ordered) == 0 {
		block = append(block, 0)
	}
	return block, nil
}
