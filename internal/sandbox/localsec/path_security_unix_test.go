//go:build !windows

package localsec

import (
	"os"
	"path/filepath"
	"testing"
)

// TestCreateDirRejectsPlantedSymlink: the sandbox state directory is the
// local control boundary; a symlink pre-planted by another account (the
// shared-temp fallback scenario) must fail closed.
func TestCreateDirRejectsPlantedSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "sandbox")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := CreateDir(link); err == nil {
		t.Fatal("CreateDir followed a symlinked sandbox directory")
	}
}

func TestCreateDirRejectsForeignOwnedDir(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to plant a directory owned by another account")
	}
	dir := t.TempDir()
	foreign := filepath.Join(dir, "foreign")
	if err := os.MkdirAll(foreign, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(foreign, 1, 1); err != nil {
		t.Fatal(err)
	}
	if err := CreateDir(foreign); err == nil {
		t.Fatal("CreateDir accepted a directory owned by another account")
	}
}

func TestCreateDirCreatesPrivateDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fresh", "sandbox")
	if err := CreateDir(path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("mode = %o, want 0700", info.Mode().Perm())
	}
	if err := CreateDir(path); err != nil {
		t.Fatalf("CreateDir on an existing own directory: %v", err)
	}
}
