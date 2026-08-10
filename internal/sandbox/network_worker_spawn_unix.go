//go:build linux || darwin

package sandbox

import (
	"fmt"
	"net"
	"os"
	"syscall"
)

// socketpairConn returns both ends of an AF_UNIX SOCK_STREAM socketpair
// as net.Conns (the portable baseline for the worker channels;
// SOCK_SEQPACKET is a documented benchmark candidate, not a requirement).
func socketpairConns() (a, b net.Conn, err error) {
	// Socketpair has no portable atomic CLOEXEC flag across Linux and Darwin.
	// Exclude a concurrent fork/exec until both raw descriptors are marked so
	// an unrelated child can never inherit a worker channel capability.
	syscall.ForkLock.RLock()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err == nil {
		syscall.CloseOnExec(fds[0])
		syscall.CloseOnExec(fds[1])
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		return nil, nil, fmt.Errorf("socketpair: %w", err)
	}
	mk := func(fd int, name string) (net.Conn, error) {
		f := os.NewFile(uintptr(fd), name)
		defer func() { _ = f.Close() }()
		return net.FileConn(f)
	}
	a, err = mk(fds[0], "socketpair-a")
	if err != nil {
		_ = syscall.Close(fds[1])
		return nil, nil, err
	}
	b, err = mk(fds[1], "socketpair-b")
	if err != nil {
		_ = a.Close()
		return nil, nil, err
	}
	return a, b, nil
}

// spawnNetWorkerProcess re-executes this exact binary in the hidden
// _net-worker role with the control (fd 3) and data (fd 4) socketpair
// ends as its only inherited descriptors. The role argument carries no
// authority — the inherited channels do — and the environment is an
// explicit allowlist so no daemon-held secret leaks into the child.
// stderrPath, when non-empty, receives a bounded worker diagnostic stream.
// The child inherits only a write-only pipe; the supervisor retains sole
// ownership of the regular file.
func spawnNetWorkerProcess(stderrPath, confinement string) (control, data net.Conn, cmd *os.Process, diagnostics *boundedLogPipe, err error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("worker re-exec path: %w", err)
	}
	ctrlSup, ctrlWrk, err := socketpairConns()
	if err != nil {
		return nil, nil, nil, nil, err
	}
	dataSup, dataWrk, err := socketpairConns()
	if err != nil {
		_ = ctrlSup.Close()
		_ = ctrlWrk.Close()
		return nil, nil, nil, nil, err
	}
	keepSupervisorEnds := false
	defer func() {
		if !keepSupervisorEnds {
			_ = ctrlSup.Close()
			_ = dataSup.Close()
		}
	}()
	argv := []string{exe, "_net-worker"}
	env := networkWorkerEnv()
	if netWorkerSpawnHook != nil {
		// Tests re-execute the TEST binary, not gantry: the hook swaps
		// argv/env to the helper-process entry point instead.
		netWorkerSpawnHook(&argv, &env)
	}
	// ExtraFiles needs *os.File handles that survive exec: dup the conns
	// back to plain files. The child's fd numbering is 3,4 in slice order.
	childFiles, err := dupConnFiles(ctrlWrk, dataWrk)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("worker descriptor table: %w", err)
	}
	defer closeFiles(childFiles)

	workerLog, err := newBoundedLogPipe(stderrPath)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("open network worker log broker: %w", err)
	}
	keepWorkerLog := false
	defer func() {
		if !keepWorkerLog {
			_ = workerLog.Close()
		}
	}()
	diagnostic := workerLog.Writer()
	start := func(namespaced bool) (*os.Process, error) {
		sys := workerSysProcAttr()
		if namespaced {
			workerConfineProcAttr(sys)
		}
		return os.StartProcess(exe, argv, &os.ProcAttr{
			Env: env,
			// fd 0 cannot expose the daemon's secrets handshake; fd 1/2 cannot
			// seek, truncate, or grow daemon.log/worker-net.log directly.
			Files: []*os.File{diagnostic, diagnostic, diagnostic, childFiles[0], childFiles[1]},
			Sys:   sys,
		})
	}
	namespaced := confinement != "off"
	proc, err := start(namespaced)
	if err != nil && confinement == "auto" && isNamespaceUnavailable(err) {
		fmt.Fprintf(os.Stderr, "network worker: confined spawn denied (%v); retrying without namespaces\n", err)
		proc, err = start(false)
	}
	workerLog.ReleaseWriter()
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("spawn net-worker: %w", err)
	}
	// The drain goroutine self-owns the file until process EOF.
	keepWorkerLog = true
	keepSupervisorEnds = true
	return ctrlSup, dataSup, proc, workerLog, nil
}

// connFile extracts a dup'd *os.File from a socket net.Conn.
func connFile(c net.Conn) (*os.File, error) {
	type filer interface{ File() (*os.File, error) }
	f, ok := c.(filer)
	if !ok {
		return nil, fmt.Errorf("conn %T cannot expose its fd", c)
	}
	return f.File()
}

// dupConnFiles transfers ownership of conns to this helper, closes every
// source connection, and returns the duplicated files needed by ExtraFiles.
// A partial failure also closes every duplicate already created.
func dupConnFiles(conns ...net.Conn) ([]*os.File, error) {
	files := make([]*os.File, 0, len(conns))
	defer func() {
		for _, c := range conns {
			if c != nil {
				_ = c.Close()
			}
		}
	}()
	for i, c := range conns {
		f, fileErr := connFile(c)
		if fileErr != nil {
			closeFiles(files)
			return nil, fmt.Errorf("connection %d: %w", i, fileErr)
		}
		files = append(files, f)
	}
	return files, nil
}

func closeFiles(files []*os.File) {
	for _, f := range files {
		if f != nil {
			_ = f.Close()
		}
	}
}

// netWorkerSpawnHook, when set, rewrites the re-exec argv/env (tests
// only: os.Executable() is the test binary under `go test`).
var netWorkerSpawnHook func(argv *[]string, env *[]string)

// workerEnv is the explicit child environment allowlist: no secret
// material, no GANTRY_* knobs (those travel in the bootstrap config).
func workerEnv() []string {
	out := make([]string, 0, 1)
	// GANTRY_DEBUG_RTC is a debug pass-through (worker-side postmortem
	// logging); it carries no secret material.
	if os.Getenv("GANTRY_DEBUG_RTC") != "" {
		out = append(out, "GANTRY_DEBUG_RTC=1")
	}
	return out
}

// networkWorkerEnv selects the pure-Go resolver before package initialization
// in the re-exec'd child. It uses only the private resolver-file snapshot and
// ordinary UDP/TCP sockets, avoiding Darwin's mDNSResponder Unix socket and
// libc NSS module loading after path access has been removed.
func networkWorkerEnv() []string {
	return append(workerEnv(), "GODEBUG=netdns=go")
}
