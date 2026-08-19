// Package layout owns the on-disk layout of the gantry sandbox home and the
// liveness checks that go with it: where a sandbox's state directory lives,
// which names are legal inside it, and whether the daemon that owns it is
// still running.
//
// It sits below every sandbox subsystem (configuration, control, import,
// manager) so those packages can resolve paths and probe liveness without
// importing the orchestration facade back — which would be an import cycle.
//
// State per sandbox under ~/.gantry/sandboxes/<name>/:
//
//	sandbox.json      start configuration (images, rw, shares, net)
//	vmm.pid           daemon process id (written by the daemon once it holds vmm.lock)
//	ready             touched once the guest RPC connection is held
//	ctl.sock          session broker (JSON line, then raw stdio)
//	1025.sock         vsock dial-back accept target
//	listen-1026.sock  vsock stream listener
//	console.log       guest serial console
//	gvproxy.log       network backend log
//	daemon.log        daemon stdout/stderr
//	daemon.log.previous  preceding run's daemon log (survives restart)
package layout

import (
	"fmt"
	"os"
	"path/filepath"
)

// Root is the sandbox home: every sandbox state directory lives directly
// under it. GANTRY_HOME overrides it (tests point it at a temp directory).
func Root() string {
	if d := os.Getenv("GANTRY_HOME"); d != "" {
		return d
	}
	home, err := os.UserHomeDir()
	if err != nil {
		// A fixed name under a world-writable directory would let another
		// local user pre-plant the state tree (and gantry would follow a
		// symlink there). Fall back to a per-account subdirectory instead.
		home = filepath.Join(os.TempDir(), fmt.Sprintf("gantry-%d", os.Getuid()))
	}
	return filepath.Join(home, ".gantry", "sandboxes")
}

// Dir is the state directory for one sandbox. Callers must have validated
// name first (see ValidateName); Dir itself does not, so that path
// construction stays allocation-cheap on hot paths.
func Dir(name string) string { return filepath.Join(Root(), name) }

// ValidName reports whether name is safe to join onto Root.
func ValidName(name string) bool {
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

// ValidateName rejects names that are empty, overlong, pure dots (path
// traversal — `delete` feeds the joined path to os.RemoveAll) or contain
// anything but letters, digits and ._-. The CLI dispatch layer (main.go)
// turns the error into an exit code; the library itself never exits.
func ValidateName(name string) error {
	if !ValidName(name) {
		return fmt.Errorf("invalid sandbox name %q (letters, digits, ._-; not . or ..)", name)
	}
	return nil
}

// PID reports the daemon pid recorded for name and whether it is alive.
func PID(name string) (int, bool) {
	b, err := os.ReadFile(filepath.Join(Dir(name), "vmm.pid"))
	if err != nil {
		return 0, false
	}
	var pid int
	_, _ = fmt.Sscanf(string(b), "%d", &pid)
	if pid <= 0 {
		return 0, false
	}
	if !ProcAlive(pid) {
		return pid, false // stale pid file
	}
	// A bare pid can be recycled by the OS into an unrelated process, so a
	// live pid alone is never accepted as proof of life: the daemon writes
	// vmm.pid itself only after acquiring vmm.lock and holds that lock for
	// its whole lifetime (the OS releases it when the process dies, before
	// the pid can be reused). No lock means the recorded pid is stale.
	if !LockHeld(Dir(name)) {
		return pid, false
	}
	return pid, true
}

// AbsPath resolves p against the working directory, falling back to p when
// that is not possible.
func AbsPath(p string) string {
	if abs, err := filepath.Abs(p); err == nil {
		return abs
	}
	return p
}
