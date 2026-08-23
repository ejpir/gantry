package worker

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/ejpir/gantry/internal/workerproto"
)

const windowsWorkerProbePathEnv = "GANTRY_WORKER_PROBE_READ_PATH"
const windowsWorkerProbeNetEnv = "GANTRY_WORKER_PROBE_NET_ADDR"

type windowsJob struct {
	handle        windows.Handle
	probePath     string
	probeListener net.Listener
}

func (job *windowsJob) Close() error {
	if job == nil {
		return nil
	}
	var result error
	if job.handle != 0 {
		result = windows.CloseHandle(job.handle)
		job.handle = 0
	}
	if job.probePath != "" {
		if err := os.Remove(job.probePath); err != nil && !os.IsNotExist(err) {
			result = errors.Join(result, err)
		}
		job.probePath = ""
	}
	if job.probeListener != nil {
		result = errors.Join(result, job.probeListener.Close())
		job.probeListener = nil
	}
	return result
}

func prepareWindowsJob() (*windowsJob, error) {
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
	return job, nil
}

func (job *windowsJob) assignHandle(process windows.Handle, pid int) error {
	if job == nil || job.handle == 0 {
		return nil
	}
	if err := windows.AssignProcessToJobObject(job.handle, process); err != nil {
		return fmt.Errorf("assign worker PID %d to job: %w", pid, err)
	}
	return nil
}

func StartWindowsProcess(exe string, argv, env []string, files []*os.File,
	handles []syscall.Handle, role workerproto.Role, confinement string) (*os.Process, Containment, error) {
	unconfinedEnv := append([]string(nil), env...)
	startUnconfined := func() (*os.Process, error) {
		return os.StartProcess(exe, argv, &os.ProcAttr{
			Env: unconfinedEnv, Files: files,
			Sys: WindowsSysProcAttr(0, handles),
		})
	}
	if confinement == "" || confinement == "off" {
		process, err := startUnconfined()
		return process, nil, err
	}

	// AppContainer creation needs the user-profile environment roots even
	// though the zero-capability token cannot open those host paths.
	env = appendMissingWindowsEnvironment(env,
		"USERPROFILE", "LOCALAPPDATA", "APPDATA", "ProgramData")

	probe, err := os.CreateTemp("", "gantry-workerconf-read-*")
	if err != nil {
		if confinement == "required" {
			return nil, nil, fmt.Errorf("create Windows confinement probe: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Windows worker filesystem probe unavailable: %v; retrying unconfined\n", err)
		process, startErr := startUnconfined()
		return process, nil, startErr
	}
	probePath := probe.Name()
	if _, err := probe.WriteString("supervisor-private confinement sentinel\n"); err != nil {
		_ = probe.Close()
		_ = os.Remove(probePath)
		return nil, nil, fmt.Errorf("write Windows confinement probe: %w", err)
	}
	if err := probe.Close(); err != nil {
		_ = os.Remove(probePath)
		return nil, nil, fmt.Errorf("close Windows confinement probe: %w", err)
	}
	probeListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		_ = os.Remove(probePath)
		if confinement == "required" {
			return nil, nil, fmt.Errorf("create Windows confinement network probe: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Windows worker network probe unavailable: %v; retrying unconfined\n", err)
		process, startErr := startUnconfined()
		return process, nil, startErr
	}
	env = append(append([]string(nil), env...),
		windowsWorkerProbePathEnv+"="+probePath,
		windowsWorkerProbeNetEnv+"="+probeListener.Addr().String())

	job, err := prepareWindowsJob()
	if err != nil {
		_ = probeListener.Close()
		_ = os.Remove(probePath)
		if confinement == "required" {
			return nil, nil, err
		}
		fmt.Fprintf(os.Stderr, "Windows worker job confinement unavailable: %v; retrying unconfined\n", err)
		process, startErr := startUnconfined()
		return process, nil, startErr
	}
	job.probePath = probePath
	job.probeListener = probeListener

	// WHPX rejects AppContainer tokens at WHvCreatePartition, so only the
	// brokered topology may place the VMM's device half in AppContainer. The
	// narrow RoleWHPX child retains the partition under a Job-only boundary.
	brokeredVMM := role == workerproto.RoleVMM && environmentContains(env, "GANTRY_WINDOWS_WHPX_BROKER_ACTIVE=1")
	appContainerEligible := role == workerproto.RoleMCP || brokeredVMM
	appContainerRequired := appContainerEligible && confinement == "required"
	useAppContainer := appContainerEligible && os.Getenv("GANTRY_WINDOWS_APPCONTAINER") != "0"
	var profile *windowsAppContainerProfile
	if useAppContainer {
		profile, err = openWindowsWorkerAppContainer()
		if err != nil {
			if appContainerRequired {
				_ = job.Close()
				return nil, nil, err
			}
			fmt.Fprintf(os.Stderr, "Windows worker AppContainer unavailable: %v; using Job-only confinement\n", err)
		}
	}
	if profile != nil {
		defer func() { _ = profile.Close() }()
	}

	startSuspended := func(sid *windows.SID) (*windowsCreatedProcess, error) {
		return createWindowsProcessSuspended(exe, argv, env, files, handles, sid)
	}
	var appContainerSID *windows.SID
	if profile != nil {
		appContainerSID = profile.sid
	}
	created, err := startSuspended(appContainerSID)
	if err != nil && appContainerSID != nil && errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		// Unpackaged binaries outside Windows/Program Files do not necessarily
		// carry an ALL APPLICATION PACKAGES execute ACE. Grant this one private
		// AppContainer identity read/execute access to the current binary only.
		if aclErr := grantAppContainerExecutableAccess(exe, appContainerSID); aclErr == nil {
			created, err = startSuspended(appContainerSID)
		} else {
			err = errors.Join(err, aclErr)
		}
	}
	if err != nil && appContainerSID != nil && !appContainerRequired {
		fmt.Fprintf(os.Stderr, "Windows worker AppContainer launch failed: %v; using Job-only confinement\n", err)
		created, err = startSuspended(nil)
	}
	if err != nil {
		_ = job.Close()
		if appContainerRequired {
			return nil, nil, fmt.Errorf("launch required AppContainer worker: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Windows worker confined launch failed: %v; retrying unconfined\n", err)
		process, startErr := startUnconfined()
		return process, nil, startErr
	}

	if err := job.assignHandle(created.processHandle, created.process.Pid); err != nil {
		if confinement == "required" {
			created.abort()
			_ = job.Close()
			return nil, nil, err
		}
		fmt.Fprintf(os.Stderr, "Windows worker job assignment failed: %v; continuing without job containment\n", err)
		_ = windows.CloseHandle(job.handle)
		job.handle = 0
	}
	if err := created.resume(); err != nil {
		created.abort()
		_ = job.Close()
		return nil, nil, err
	}
	created.closeCreationHandles()
	return created.process, job, nil
}

func environmentContains(environment []string, entry string) bool {
	for _, candidate := range environment {
		if candidate == entry {
			return true
		}
	}
	return false
}

func appendMissingWindowsEnvironment(environment []string, names ...string) []string {
	result := append([]string(nil), environment...)
	present := make(map[string]struct{}, len(result))
	for _, entry := range result {
		name, _, ok := strings.Cut(entry, "=")
		if ok {
			present[strings.ToUpper(name)] = struct{}{}
		}
	}
	for _, name := range names {
		if _, exists := present[strings.ToUpper(name)]; exists {
			continue
		}
		if value := os.Getenv(name); value != "" {
			result = append(result, name+"="+value)
		}
	}
	return result
}
