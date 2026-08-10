package sandbox

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// Sandbox lifecycle: create/start/stop/ls/delete + exec.
// A sandbox is a long-lived VMM daemon holding the single
// vsock dial-back ttrpc connection vminitd makes per VM lifetime
// (dialBackListener dials exactly once). `gantry exec <name>` is a thin
// client; the daemon multiplexes sessions over that one connection (ttrpc
// streams are independent, so concurrent exec sessions are fine).
//
// State per sandbox under ~/.gantry/sandboxes/<name>/:
//
//	sandbox.json      start configuration (images, rw, shares, net)
//	vmm.pid           daemon process id
//	ready             touched once the guest RPC connection is held
//	ctl.sock          session broker (JSON line, then raw stdio)
//	1025.sock         vsock dial-back accept target
//	listen-1026.sock  vsock stream listener
//	console.log       guest serial console
//	gvproxy.log       network backend log
//	daemon.log        daemon stdout/stderr

func sandboxRoot() string {
	if d := os.Getenv("GANTRY_HOME"); d != "" {
		return d
	}
	home, err := os.UserHomeDir()
	if err != nil {
		home = "/tmp"
	}
	return filepath.Join(home, ".gantry", "sandboxes")
}

func sandboxDir(name string) string { return filepath.Join(sandboxRoot(), name) }

func validSandboxName(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	// pure dots are path traversal (filepath.Join(root, "..") escapes the
	// sandbox root — and `delete` feeds the result to os.RemoveAll).
	if name == "." || name == ".." {
		return false
	}
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}

// ValidateSandboxName rejects names that are empty, overlong, pure dots
// (path traversal — `delete` feeds the joined path to os.RemoveAll) or
// contain anything but letters, digits and ._-. The CLI dispatch layer
// (main.go) turns the error into an exit code; the library itself never
// exits.
func ValidateSandboxName(name string) error {
	if !validSandboxName(name) {
		return fmt.Errorf("invalid sandbox name %q (letters, digits, ._-; not . or ..)", name)
	}
	return nil
}

func sandboxPID(name string) (int, bool) {
	b, err := os.ReadFile(filepath.Join(sandboxDir(name), "vmm.pid"))
	if err != nil {
		return 0, false
	}
	var pid int
	_, _ = fmt.Sscanf(string(b), "%d", &pid)
	if pid <= 0 {
		return 0, false
	}
	if !procAlive(pid) {
		return pid, false // stale pid file
	}
	// A bare pid can be recycled by the OS into an unrelated process;
	// require the daemon's flock on vmm.lock as proof of life. Grace
	// window: between the spawner writing vmm.pid and the daemon
	// acquiring the lock, a fresh pid file alone counts as alive.
	if !sandboxLockHeld(sandboxDir(name)) {
		st, err := os.Stat(filepath.Join(sandboxDir(name), "vmm.pid"))
		if err != nil || time.Since(st.ModTime()) > 10*time.Second {
			return pid, false
		}
	}
	return pid, true
}

func absPath(p string) string {
	if abs, err := filepath.Abs(p); err == nil {
		return abs
	}
	return p
}

func dumpTail(path string) {
	dumpTailTo(os.Stderr, path)
}

func dumpTailTo(w io.Writer, path string) {
	b, err := readFileTail(path, 4096)
	if err != nil || len(b) == 0 {
		return
	}
	_, _ = fmt.Fprintf(w, "---- last bytes of %s ----\n%s\n----\n", filepath.Base(path), b)
}

// readFileTail allocates in proportion to the requested tail, never the file.
// Logs are attacker-influenced and may also predate the bounded log broker.
func readFileTail(path string, limit int64) ([]byte, error) {
	if limit <= 0 {
		return nil, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	end, err := file.Seek(0, io.SeekEnd)
	if err != nil {
		return nil, err
	}
	start := end - limit
	if start < 0 {
		start = 0
	}
	if _, err := file.Seek(start, io.SeekStart); err != nil {
		return nil, err
	}
	return io.ReadAll(io.LimitReader(file, limit))
}
