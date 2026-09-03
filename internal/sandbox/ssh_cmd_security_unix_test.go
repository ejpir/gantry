//go:build !windows

package sandbox

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEnsureSSHKnownHostsCreatesPrivateRegularFile(t *testing.T) {
	base := t.TempDir()
	t.Setenv("GANTRY_HOME", filepath.Join(base, "sandboxes"))
	if err := ensureSSHKnownHostsFile(); err != nil {
		t.Fatal(err)
	}
	if err := ensureSSHKnownHostsFile(); err != nil {
		t.Fatalf("second ensure: %v", err)
	}
	info, err := os.Lstat(filepath.Join(sshInstallDir(), "known_hosts"))
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("known_hosts mode = %v, want regular 0600", info.Mode())
	}
}

func TestEnsureSSHKnownHostsRejectsSymlinkBeforeSideEffects(t *testing.T) {
	base := t.TempDir()
	t.Setenv("GANTRY_HOME", filepath.Join(base, "sandboxes"))
	if err := os.MkdirAll(sshInstallDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(base, "target")
	if err := os.WriteFile(target, []byte("do not touch\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0o644); err != nil {
		t.Fatal(err)
	}
	knownHosts := filepath.Join(sshInstallDir(), "known_hosts")
	if err := os.Symlink(target, knownHosts); err != nil {
		t.Fatal(err)
	}
	if err := ensureSSHKnownHostsFile(); err == nil {
		t.Fatal("symlinked known_hosts was accepted")
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("symlink target mode changed to %o", info.Mode().Perm())
	}
	contents, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != "do not touch\n" {
		t.Fatalf("symlink target contents changed to %q", contents)
	}
}
