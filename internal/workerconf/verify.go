package workerconf

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"time"
)

// Verify probes the current process's confinement and records the
// outcome in report.Results. It is safe to call unconfined (the results
// then honestly read "unenforced") and it never upgrades an
// indeterminate probe to enforced.
func Verify(spec Spec, report *Report) {
	// Stage prints: worker postmortem tooling — a mid-Verify death
	// (observed once on AL2023) names its probe here.
	staged := func(name string, fn func() PropertyResult) PropertyResult {
		_, _ = fmt.Fprintln(os.Stderr, "workerconf: probe "+name)
		r := fn()
		_, _ = fmt.Fprintf(os.Stderr, "workerconf: probe %s -> %s (%s)\n", name, r.State, r.Detail)
		return r
	}
	results := []PropertyResult{
		staged("fs-read", probeFSRead),
		staged("fs-write", probeFSWrite),
		staged("net-dial", func() PropertyResult { return probeNetDial(spec.NoNetwork) }),
		staged("exec", func() PropertyResult { return probeExec(spec.NoExec) }),
	}
	if runtime.GOOS == "linux" {
		fdTable := report.Property(PropFDTable)
		if fdTable.State == StateUnavailable {
			fdTable = PropertyResult{
				Property: PropFDTable,
				State:    StateIndeterminate,
				Detail:   "descriptor close outcome unavailable",
			}
		}
		results = append(results, fdTable)
		syscallPolicy := report.Property(PropSyscall)
		if syscallPolicy.State == StateUnavailable {
			syscallPolicy = PropertyResult{
				Property: PropSyscall,
				State:    StateIndeterminate,
				Detail:   "seccomp installation outcome unavailable",
			}
		}
		results = append(results, syscallPolicy)
		results = append(results, staged("proc-enum", probeProcEnum))
		taskLimit := report.Property(PropTaskLimit)
		if taskLimit.State == StateUnavailable {
			taskLimit = staged("task-limit", func() PropertyResult { return probeTaskLimit(spec.MaxTasks) })
		} else {
			_, _ = fmt.Fprintf(os.Stderr, "workerconf: probe task-limit -> %s (%s)\n", taskLimit.State, taskLimit.Detail)
		}
		results = append(results, taskLimit)
	}
	// proc-signal is a Darwin Seatbelt property. Omitting it elsewhere keeps
	// Linux reports from treating a deliberately unavailable platform probe as
	// a degraded applied property; Property still reports it unavailable.
	if runtime.GOOS == "darwin" {
		results = append(results,
			staged("proc-enum", probeProcEnum),
			staged("proc-signal", func() PropertyResult { return probeProcSignal(spec.NoProcX) }),
		)
	}
	report.Results = results
}

// probeFSRead opens a well-known host file. Under confinement the open
// must fail (ENOENT in the empty private root, EPERM under a path
// filter); success means the worker can still read user files.
func probeFSRead() PropertyResult {
	f, err := os.Open(probeReadPath)
	if err != nil {
		return PropertyResult{Property: PropFSRead, State: StateEnforced, Detail: errString(err)}
	}
	_ = f.Close()
	return PropertyResult{Property: PropFSRead, State: StateUnenforced, Detail: "opened " + probeReadPath}
}

// probeFSWrite creates a file in the user's HOME (or temp dir). The
// private root contains neither path, so confined creation fails; an
// unconfined success is cleaned up immediately.
func probeFSWrite() PropertyResult {
	dir := os.Getenv("HOME")
	if dir == "" {
		dir = os.TempDir()
	}
	path := filepath.Join(dir, fmt.Sprintf(".workerconf-probe-%d", os.Getpid()))
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return PropertyResult{Property: PropFSWrite, State: StateEnforced, Detail: errString(err)}
	}
	_ = f.Close()
	_ = os.Remove(path)
	return PropertyResult{Property: PropFSWrite, State: StateUnenforced, Detail: "created " + path}
}

// probeNetDial dials loopback port 1: nothing listens there, so an
// unconfined process gets a fast ECONNREFUSED, while a confined one
// fails earlier with EPERM at socket()/connect(). A timeout proves
// nothing and is indeterminate.
func probeNetDial(noNetwork bool) PropertyResult {
	if !noNetwork {
		return PropertyResult{Property: PropNetDial, State: StateDisabled}
	}
	conn, err := net.DialTimeout("tcp", "127.0.0.1:1", 500*time.Millisecond)
	if err == nil {
		_ = conn.Close()
		return PropertyResult{Property: PropNetDial, State: StateUnenforced, Detail: "connected to 127.0.0.1:1"}
	}
	if os.IsPermission(err) || errors.Is(err, syscall.EPERM) {
		return PropertyResult{Property: PropNetDial, State: StateEnforced, Detail: errString(err)}
	}
	if isConnectionRefused(err) {
		return PropertyResult{Property: PropNetDial, State: StateUnenforced, Detail: "connection refused (socket syscalls work)"}
	}
	return PropertyResult{Property: PropNetDial, State: StateIndeterminate, Detail: errString(err)}
}

// probeExec re-execs the current binary with a benign flag. Only the
// spawn matters: a started child proves exec works, whatever its exit
// status, so the child is killed immediately.
func probeExec(noExec bool) PropertyResult {
	if !noExec {
		return PropertyResult{Property: PropExec, State: StateDisabled}
	}
	cmd := exec.Command(os.Args[0], "--workerconf-probe")
	cmd.Stdout, cmd.Stderr = nil, nil
	err := cmd.Start()
	if err == nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return PropertyResult{Property: PropExec, State: StateUnenforced, Detail: "spawned " + os.Args[0]}
	}
	return PropertyResult{Property: PropExec, State: StateEnforced, Detail: errString(err)}
}

// evaluateProcSignalProbe classifies the Darwin signal(0) probe. signal(0)
// performs permission and liveness checks without delivering a signal. The
// self call is a positive control: without it, a broken probe could be
// mistaken for cross-process confinement.
func evaluateProcSignalProbe(noProcX bool, selfPID, parentPID int, signal0 func(int) error) PropertyResult {
	if !noProcX {
		return PropertyResult{Property: PropProcSignal, State: StateDisabled}
	}
	if selfPID <= 0 {
		return PropertyResult{Property: PropProcSignal, State: StateIndeterminate, Detail: "invalid self PID"}
	}
	if err := signal0(selfPID); err != nil {
		return PropertyResult{
			Property: PropProcSignal, State: StateIndeterminate,
			Detail: fmt.Sprintf("self kill(%d, 0) positive control: %s", selfPID, errString(err)),
		}
	}
	// A worker's live supervisor parent is a distinct, same-UID process.
	// PID 1 instead indicates reparenting and cannot prove Seatbelt policy:
	// ordinary discretionary permissions may reject signaling launchd.
	if parentPID <= 1 || parentPID == selfPID {
		return PropertyResult{
			Property: PropProcSignal, State: StateIndeterminate,
			Detail: fmt.Sprintf("no distinct live parent PID (got %d)", parentPID),
		}
	}
	err := signal0(parentPID)
	switch {
	case err == nil:
		return PropertyResult{
			Property: PropProcSignal, State: StateUnenforced,
			Detail: fmt.Sprintf("kill(parent PID %d, 0) succeeded", parentPID),
		}
	case errors.Is(err, syscall.EPERM):
		return PropertyResult{
			Property: PropProcSignal, State: StateEnforced,
			Detail: fmt.Sprintf("kill(parent PID %d, 0): %s", parentPID, errString(err)),
		}
	case errors.Is(err, syscall.ESRCH):
		return PropertyResult{
			Property: PropProcSignal, State: StateIndeterminate,
			Detail: fmt.Sprintf("parent PID %d disappeared: %s", parentPID, errString(err)),
		}
	default:
		return PropertyResult{
			Property: PropProcSignal, State: StateIndeterminate,
			Detail: fmt.Sprintf("kill(parent PID %d, 0): %s", parentPID, errString(err)),
		}
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	if pe, ok := err.(*os.PathError); ok {
		return pe.Op + ": " + pe.Err.Error()
	}
	return err.Error()
}
