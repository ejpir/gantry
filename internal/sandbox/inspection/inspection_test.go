package inspection

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/layout"
)

func TestInspectDistinguishesReadinessAndDesiredAllocation(t *testing.T) {
	t.Setenv("GANTRY_HOME", t.TempDir())
	name := "dev"
	dir := layout.Dir(name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := config.RunConfig{MemMB: 512, VCPUs: 1}
	if err := config.WriteSandboxConfig(dir, cfg); err != nil {
		t.Fatal(err)
	}
	check := func(want State) Snapshot {
		t.Helper()
		got, err := Inspect(name)
		if err != nil || got.ConfigError != nil || got.State != want {
			t.Fatalf("Inspect=%+v error=%v, want %s", got, err, want)
		}
		return got
	}
	check(Stopped)
	lock, err := layout.HoldLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Close() }()
	check(Starting) // Acquiring the lifetime lock precedes publishing the PID.
	if err := os.WriteFile(filepath.Join(dir, "vmm.pid"), []byte(fmt.Sprint(os.Getpid())), 0o600); err != nil {
		t.Fatal(err)
	}
	check(Starting)
	if err := PublishActive(dir, cfg); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ready"), []byte("1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := check(Running)
	if got.Active == nil || got.RestartRequired {
		t.Fatalf("active=%+v", got)
	}
	cfg.MemMB = 1024
	if err := config.WriteSandboxConfig(dir, cfg); err != nil {
		t.Fatal(err)
	}
	got = check(Running)
	if got.Active.MemoryMiB != 512 || got.Desired.MemMB != 1024 || !got.RestartRequired {
		t.Fatalf("allocation=%+v", got)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	got = check(Stopped)
	if got.Active != nil || got.RestartRequired {
		t.Fatalf("stopped sandbox used stale boot metadata: %+v", got)
	}
}

func TestInspectRetainsInvalidConfigurationAsDiagnostic(t *testing.T) {
	t.Setenv("GANTRY_HOME", t.TempDir())
	dir := layout.Dir("broken")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sandbox.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := Inspect("broken")
	if err != nil || got.ConfigError == nil || got.Name != "broken" {
		t.Fatalf("Inspect=%+v error=%v", got, err)
	}
}
