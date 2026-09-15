//go:build windows

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// runTerminalBridge launches the real Gantry TUI inside a Windows ConPTY and
// relays its terminal byte stream over this helper's stdin/stdout. The Python
// screen driver can therefore exercise the native Windows binary without a
// VM, a Unix compatibility layer, or an interactive Actions console.
func runTerminalBridge(gantry string) (int, error) {
	var inputRead, inputWrite windows.Handle
	if err := windows.CreatePipe(&inputRead, &inputWrite, nil, 0); err != nil {
		return 1, fmt.Errorf("create ConPTY input pipe: %w", err)
	}
	defer func() {
		if inputRead != 0 {
			_ = windows.CloseHandle(inputRead)
		}
		if inputWrite != 0 {
			_ = windows.CloseHandle(inputWrite)
		}
	}()

	var outputRead, outputWrite windows.Handle
	if err := windows.CreatePipe(&outputRead, &outputWrite, nil, 0); err != nil {
		return 1, fmt.Errorf("create ConPTY output pipe: %w", err)
	}
	defer func() {
		if outputRead != 0 {
			_ = windows.CloseHandle(outputRead)
		}
		if outputWrite != 0 {
			_ = windows.CloseHandle(outputWrite)
		}
	}()

	var console windows.Handle
	if err := windows.CreatePseudoConsole(windows.Coord{X: 120, Y: 54}, inputRead, outputWrite, 0, &console); err != nil {
		return 1, fmt.Errorf("create Windows pseudoconsole: %w", err)
	}
	defer func() {
		if console != 0 {
			windows.ClosePseudoConsole(console)
		}
	}()

	attributes, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		return 1, fmt.Errorf("allocate ConPTY process attributes: %w", err)
	}
	defer attributes.Delete()
	// PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE takes the HPCON value itself, unlike
	// attributes such as PARENT_PROCESS that take a pointer to a handle.
	consoleValue := *(*unsafe.Pointer)(unsafe.Pointer(&console))
	if err := attributes.Update(windows.PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, consoleValue, unsafe.Sizeof(console)); err != nil {
		return 1, fmt.Errorf("attach ConPTY process attribute: %w", err)
	}

	// Keep the TUI in a kill-on-close job. If the Python driver is interrupted
	// and terminates this bridge, Windows then tears down the child instead of
	// leaving it attached to an orphaned conhost process.
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 1, fmt.Errorf("create ConPTY process job: %w", err)
	}
	defer func() { _ = windows.CloseHandle(job) }()
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(
		job,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&limits)),
		uint32(unsafe.Sizeof(limits)),
	); err != nil {
		return 1, fmt.Errorf("configure ConPTY process job: %w", err)
	}

	application, err := windows.UTF16PtrFromString(gantry)
	if err != nil {
		return 1, fmt.Errorf("encode Gantry path: %w", err)
	}
	commandLine, err := windows.UTF16PtrFromString(windows.ComposeCommandLine([]string{gantry, "tui", "-remote="}))
	if err != nil {
		return 1, fmt.Errorf("encode Gantry command line: %w", err)
	}
	startup := windows.StartupInfoEx{}
	startup.Cb = uint32(unsafe.Sizeof(startup))
	// ConPTY substitutes its console handles for these zero-valued standard
	// handles. Without STARTF_USESTDHANDLES, a process launched by a redirected
	// CI helper can retain the helper's pipe handles and fail GetConsoleMode.
	startup.Flags = windows.STARTF_USESTDHANDLES
	startup.ProcThreadAttributeList = attributes.List()
	var process windows.ProcessInformation
	if err := windows.CreateProcess(
		application,
		commandLine,
		nil,
		nil,
		false,
		windows.EXTENDED_STARTUPINFO_PRESENT|windows.CREATE_UNICODE_ENVIRONMENT|windows.CREATE_SUSPENDED,
		nil,
		nil,
		&startup.StartupInfo,
		&process,
	); err != nil {
		return 1, fmt.Errorf("start Gantry in ConPTY: %w", err)
	}
	defer func() {
		if process.Thread != 0 {
			_ = windows.CloseHandle(process.Thread)
		}
		_ = windows.CloseHandle(process.Process)
	}()
	if err := windows.AssignProcessToJobObject(job, process.Process); err != nil {
		return 1, fmt.Errorf("assign Gantry to ConPTY process job: %w", err)
	}
	if _, err := windows.ResumeThread(process.Thread); err != nil {
		return 1, fmt.Errorf("resume Gantry in ConPTY: %w", err)
	}
	_ = windows.CloseHandle(process.Thread)
	process.Thread = 0

	// CreatePseudoConsole retains the console-facing ends. Keeping our copies
	// open would prevent the host-facing reader from observing terminal EOF.
	_ = windows.CloseHandle(inputRead)
	inputRead = 0
	_ = windows.CloseHandle(outputWrite)
	outputWrite = 0
	input := os.NewFile(uintptr(inputWrite), "conpty-input")
	inputWrite = 0
	output := os.NewFile(uintptr(outputRead), "conpty-output")
	outputRead = 0
	defer func() { _ = input.Close() }()
	defer func() { _ = output.Close() }()

	go func() {
		_, _ = io.Copy(input, os.Stdin)
		_ = input.Close()
	}()
	outputDone := make(chan error, 1)
	go func() {
		_, copyErr := io.Copy(os.Stdout, output)
		outputDone <- copyErr
	}()

	event, err := windows.WaitForSingleObject(process.Process, windows.INFINITE)
	if err != nil {
		return 1, fmt.Errorf("wait for ConPTY process: %w", err)
	}
	if event != windows.WAIT_OBJECT_0 {
		return 1, fmt.Errorf("wait for ConPTY process returned event %d", event)
	}
	var exitCode uint32
	if err := windows.GetExitCodeProcess(process.Process, &exitCode); err != nil {
		return 1, fmt.Errorf("read ConPTY process exit code: %w", err)
	}

	// Closing the pseudoconsole releases its output pipe. Drain concurrently as
	// required by the ConPTY API, then wait for EOF before returning diagnostics.
	windows.ClosePseudoConsole(console)
	console = 0
	_ = input.Close()
	if err := <-outputDone; err != nil && !errors.Is(err, windows.ERROR_BROKEN_PIPE) {
		return int(exitCode), fmt.Errorf("read ConPTY output: %w", err)
	}
	return int(exitCode), nil
}
