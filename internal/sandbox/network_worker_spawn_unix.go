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
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
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

// inheritedConn wraps a boot-time inherited descriptor (fd 3/4) as a
// net.Conn. os/exec clears close-on-exec on ExtraFiles entries, so these
// are exactly the socketpair ends the supervisor passed down.
func inheritedConn(fd uintptr, name string) (net.Conn, error) {
	f := os.NewFile(fd, name)
	if f == nil {
		return nil, fmt.Errorf("inherited %s fd %d unavailable", name, fd)
	}
	defer func() { _ = f.Close() }()
	c, err := net.FileConn(f)
	if err != nil {
		return nil, fmt.Errorf("inherited %s fd %d: %w", name, fd, err)
	}
	return c, nil
}

// spawnNetWorkerProcess re-executes this exact binary in the hidden
// _net-worker role with the control (fd 3) and data (fd 4) socketpair
// ends as its only inherited descriptors. The role argument carries no
// authority — the inherited channels do — and the environment is an
// explicit allowlist so no daemon-held secret leaks into the child.
// stderrPath, when non-empty, captures the worker's stderr into a log
// file (opened append) so a failed bootstrap leaves a postmortem; on
// open failure the worker inherits our stderr (never fatal).
func spawnNetWorkerProcess(stderrPath string) (control, data net.Conn, cmd *os.Process, err error) {
	ctrlSup, ctrlWrk, err := socketpairConns()
	if err != nil {
		return nil, nil, nil, err
	}
	dataSup, dataWrk, err := socketpairConns()
	if err != nil {
		_ = ctrlSup.Close()
		_ = ctrlWrk.Close()
		return nil, nil, nil, err
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("worker re-exec path: %w", err)
	}
	argv := []string{exe, "_net-worker"}
	env := workerEnv()
	if netWorkerSpawnHook != nil {
		// Tests re-execute the TEST binary, not gantry: the hook swaps
		// argv/env to the helper-process entry point instead.
		netWorkerSpawnHook(&argv, &env)
	}
	// ExtraFiles needs *os.File handles that survive exec: dup the conns
	// back to plain files. The child's fd numbering is 3,4 in slice order.
	childFiles := make([]*os.File, 0, 2)
	for i, c := range []net.Conn{ctrlWrk, dataWrk} {
		f, err := connFile(c)
		if err != nil {
			_ = ctrlSup.Close()
			_ = dataSup.Close()
			return nil, nil, nil, fmt.Errorf("worker fd %d: %w", i+3, err)
		}
		childFiles = append(childFiles, f)
	}
	_ = ctrlWrk.Close()
	_ = dataWrk.Close()

	workerStderr := os.Stderr
	if stderrPath != "" {
		if f, err := os.OpenFile(stderrPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600); err == nil {
			defer func() { _ = f.Close() }()
			workerStderr = f
		}
	}
	proc, err := os.StartProcess(exe, argv, &os.ProcAttr{
		Env:   env,
		Files: []*os.File{os.Stdin, os.Stdout, workerStderr, childFiles[0], childFiles[1]},
		Sys:   workerSysProcAttr(),
	})
	_ = childFiles[0].Close()
	_ = childFiles[1].Close()
	if err != nil {
		_ = ctrlSup.Close()
		_ = dataSup.Close()
		return nil, nil, nil, fmt.Errorf("spawn net-worker: %w", err)
	}
	return ctrlSup, dataSup, proc, nil
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

// netWorkerSpawnHook, when set, rewrites the re-exec argv/env (tests
// only: os.Executable() is the test binary under `go test`).
var netWorkerSpawnHook func(argv *[]string, env *[]string)

// workerEnv is the explicit child environment allowlist: no secret
// material, no GANTRY_* knobs (those travel in the bootstrap config).
func workerEnv() []string {
	out := make([]string, 0, 3)
	for _, key := range []string{"PATH", "TMPDIR", "HOME"} {
		if v, ok := os.LookupEnv(key); ok {
			out = append(out, key+"="+v)
		}
	}
	return out
}
