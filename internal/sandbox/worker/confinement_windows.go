package worker

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	createRestrictedTokenDisableMaxPrivilege = 0x1
)

var createRestrictedTokenProc = windows.NewLazySystemDLL("advapi32.dll").NewProc("CreateRestrictedToken")

type windowsJob struct {
	handle windows.Handle
}

func (job *windowsJob) Close() error {
	if job == nil || job.handle == 0 {
		return nil
	}
	err := windows.CloseHandle(job.handle)
	job.handle = 0
	return err
}

type windowsWorkerLaunch struct {
	token windows.Token
	job   *windowsJob
}

func prepareWindowsLaunch(restrictToken bool) (*windowsWorkerLaunch, error) {
	jobHandle, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("create worker job: %w", err)
	}
	job := &windowsJob{handle: jobHandle}
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
		windows.JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION |
		windows.JOB_OBJECT_LIMIT_ACTIVE_PROCESS
	limits.BasicLimitInformation.ActiveProcessLimit = 1
	if _, err := windows.SetInformationJobObject(jobHandle, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		_ = job.Close()
		return nil, fmt.Errorf("set worker job limits: %w", err)
	}
	launch := &windowsWorkerLaunch{job: job}
	if !restrictToken {
		return launch, nil
	}

	var current windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(),
		windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY|windows.TOKEN_ASSIGN_PRIMARY|windows.TOKEN_ADJUST_DEFAULT,
		&current); err != nil {
		launch.close()
		return nil, fmt.Errorf("open supervisor token: %w", err)
	}
	defer func() { _ = current.Close() }()

	restrictedSID, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	if err != nil {
		launch.close()
		return nil, fmt.Errorf("restricted-code SID: %w", err)
	}
	restricting := windows.SIDAndAttributes{Sid: restrictedSID}
	r1, _, callErr := createRestrictedTokenProc.Call(
		uintptr(current), createRestrictedTokenDisableMaxPrivilege,
		0, 0, 0, 0,
		1, uintptr(unsafe.Pointer(&restricting)),
		uintptr(unsafe.Pointer(&launch.token)),
	)
	if r1 == 0 {
		launch.close()
		return nil, fmt.Errorf("CreateRestrictedToken: %w", callErr)
	}
	return launch, nil
}

func (launch *windowsWorkerLaunch) close() {
	if launch == nil {
		return
	}
	if launch.token != 0 {
		_ = launch.token.Close()
		launch.token = 0
	}
	_ = launch.job.Close()
}

func (launch *windowsWorkerLaunch) assign(proc *os.Process) error {
	if launch == nil || launch.job == nil {
		return nil
	}
	handle, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE,
		false, uint32(proc.Pid))
	if err != nil {
		return fmt.Errorf("open worker PID %d for job: %w", proc.Pid, err)
	}
	defer func() { _ = windows.CloseHandle(handle) }()
	if err := windows.AssignProcessToJobObject(launch.job.handle, handle); err != nil {
		return fmt.Errorf("assign worker PID %d to job: %w", proc.Pid, err)
	}
	return nil
}

func StartWindowsProcess(exe string, argv, env []string, files []*os.File,
	handles []syscall.Handle, confinement string) (*os.Process, Containment, error) {
	start := func(token windows.Token) (*os.Process, error) {
		return os.StartProcess(exe, argv, &os.ProcAttr{
			Env: env, Files: files,
			Sys: WindowsSysProcAttr(token, handles),
		})
	}
	if confinement == "" || confinement == "off" {
		proc, err := start(0)
		return proc, nil, err
	}

	// A Job Object is compatible with WHPX and gives auto mode a useful,
	// verified process boundary. The stronger restricting-SID token remains
	// fail-closed for required mode (and opt-in field experiments): on current
	// Windows Server images it terminates the Go worker loader with
	// STATUS_ACCESS_DENIED before the worker can report its probes.
	restrictToken := confinement == "required" || os.Getenv("GANTRY_WINDOWS_RESTRICTED_TOKEN") == "1"
	launch, err := prepareWindowsLaunch(restrictToken)
	if err != nil {
		if confinement == "required" {
			return nil, nil, err
		}
		fmt.Fprintf(os.Stderr, "Windows worker job confinement unavailable: %v; retrying without job\n", err)
		proc, startErr := start(0)
		return proc, nil, startErr
	}
	proc, err := start(launch.token)
	_ = launch.token.Close()
	launch.token = 0
	if err != nil {
		launch.close()
		if confinement == "required" {
			return nil, nil, err
		}
		fmt.Fprintf(os.Stderr, "Windows worker launch failed: %v; retrying without token/job\n", err)
		proc, retryErr := start(0)
		return proc, nil, retryErr
	}
	if err := launch.assign(proc); err != nil {
		if confinement == "required" {
			_ = proc.Kill()
			_, _ = proc.Wait()
			launch.close()
			return nil, nil, err
		}
		fmt.Fprintf(os.Stderr, "Windows worker job assignment failed: %v; continuing without job containment\n", err)
		// An opt-in restricted token may still apply. Auto mode honestly reports
		// the missing job and any other unenforced properties through its probes.
		_ = launch.job.Close()
		launch.job = nil
		return proc, nil, nil
	}
	return proc, launch.job, nil
}
