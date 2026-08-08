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
	report.Results = []PropertyResult{
		staged("fs-read", probeFSRead),
		staged("fs-write", probeFSWrite),
		staged("net-dial", func() PropertyResult { return probeNetDial(spec.NoNetwork) }),
		staged("exec", func() PropertyResult { return probeExec(spec.NoExec) }),
		staged("proc-enum", probeProcEnum),
	}
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
	if errors.Is(err, syscall.ECONNREFUSED) {
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

// probeProcEnum checks process enumeration. Linux-only in practice: the
// confined mount namespace has no /proc at all.
func probeProcEnum() PropertyResult {
	if runtime.GOOS != "linux" {
		return PropertyResult{Property: PropProcEnum, State: StateUnavailable, Detail: "no /proc convention on " + runtime.GOOS}
	}
	f, err := os.Open("/proc")
	if err != nil {
		return PropertyResult{Property: PropProcEnum, State: StateEnforced, Detail: errString(err)}
	}
	_ = f.Close()
	return PropertyResult{Property: PropProcEnum, State: StateUnenforced, Detail: "/proc readable"}
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
