package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestInstallSelfFrom(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	source := filepath.Join(root, "source")
	want := []byte("verified guest helper\n")
	if err := os.WriteFile(source, want, 0o600); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(root, "run", "gantry", "bin")
	if err := installSelfFrom(source, destination); err != nil {
		t.Fatal(err)
	}

	helperPath := filepath.Join(destination, "gantry-guest")
	got, err := os.ReadFile(helperPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("installed content = %q, want %q", got, want)
	}
	helperInfo, err := os.Stat(helperPath)
	if err != nil {
		t.Fatal(err)
	}
	// install-self runs in a Linux guest. Windows accepts Chmod but does not
	// expose POSIX executable bits through FileMode, so only assert them where
	// the host filesystem represents them.
	if runtime.GOOS != "windows" && helperInfo.Mode().Perm() != 0o755 {
		t.Fatalf("installed mode = %o, want 755", helperInfo.Mode().Perm())
	}
	credentialInfo, err := os.Stat(filepath.Join(destination, "credhelper"))
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(helperInfo, credentialInfo) {
		t.Fatal("credhelper is not linked to the installed helper")
	}
}

func TestRunInstallSelfRejectsArguments(t *testing.T) {
	t.Parallel()
	if got := runInstallSelf([]string{"/tmp/attacker-controlled"}); got != 2 {
		t.Fatalf("status = %d, want 2", got)
	}
}
