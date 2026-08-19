//go:build linux || darwin

package layout

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// TestRootFallsBackToPerAccountTempDir guards the no-home-directory case:
// the fallback must not be a fixed name in a world-writable directory that
// another local user could pre-plant.
func TestRootFallsBackToPerAccountTempDir(t *testing.T) {
	t.Setenv("GANTRY_HOME", "")
	t.Setenv("HOME", "") // os.UserHomeDir fails on unix without $HOME
	want := filepath.Join(os.TempDir(), fmt.Sprintf("gantry-%d", os.Getuid()), ".gantry", "sandboxes")
	if got := Root(); got != want {
		t.Fatalf("Root() = %q, want per-account fallback %q", got, want)
	}
}

// TestPIDRequiresHeldDaemonLock: a live process id in vmm.pid is never
// enough — the daemon publishes its pid only while holding vmm.lock, and a
// pid recycled after an early daemon death must not be accepted.
func TestPIDRequiresHeldDaemonLock(t *testing.T) {
	t.Setenv("GANTRY_HOME", t.TempDir())
	name := "lockbox"
	if err := os.MkdirAll(Dir(name), 0o700); err != nil {
		t.Fatal(err)
	}
	pidFile := filepath.Join(Dir(name), "vmm.pid")
	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, alive := PID(name); alive {
		t.Fatal("live pid without the daemon lock treated as alive")
	}
	lock, err := HoldLock(Dir(name))
	if err != nil {
		t.Fatal(err)
	}
	if _, alive := PID(name); !alive {
		t.Fatal("daemon holding the lifetime lock not detected as alive")
	}
	_ = lock.Close()
	if _, alive := PID(name); alive {
		t.Fatal("released daemon lock still treated as alive")
	}
}
