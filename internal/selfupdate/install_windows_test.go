//go:build windows

package selfupdate

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func unelevated(t *testing.T) {
	t.Helper()
	old := processElevation
	processElevation = func() (bool, error) { return false, nil }
	t.Cleanup(func() { processElevation = old })
}

func TestWindowsUpdateProtectsElevatedPayload(t *testing.T) {
	old := processElevation
	processElevation = func() (bool, error) { return true, nil }
	t.Cleanup(func() { processElevation = old })

	staged := filepath.Join(t.TempDir(), "gantry.update.exe")
	if err := os.WriteFile(staged, []byte("verified"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := protectStagedUpdate(staged); err != nil {
		t.Fatal(err)
	}
	descriptor, err := windows.GetNamedSecurityInfo(staged, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		t.Fatal(err)
	}
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	if !owner.Equals(administrators) {
		t.Fatalf("staged update owner = %s, want %s", owner, administrators)
	}
	control, _, err := descriptor.Control()
	if err != nil {
		t.Fatal(err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatalf("staged update DACL control = %#x, want SE_DACL_PROTECTED", control)
	}
}

func TestWindowsUpdateFailsClosedWhenElevationQueryFails(t *testing.T) {
	old := processElevation
	wantErr := errors.New("token query failed")
	processElevation = func() (bool, error) { return false, wantErr }
	t.Cleanup(func() { processElevation = old })

	if err := installStaged("staged", "target"); !errors.Is(err, wantErr) {
		t.Fatalf("installStaged elevation query error = %v, want %v", err, wantErr)
	}
}

func TestWindowsInstallStagedReplacesTarget(t *testing.T) {
	unelevated(t)

	dir := t.TempDir()
	target := filepath.Join(dir, "gantry.exe")
	staged := filepath.Join(dir, "gantry update ' verified.exe")
	if err := os.WriteFile(target, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(staged, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := installStaged(staged, target); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != "new" {
		t.Fatalf("target contents = %q, want new", contents)
	}
	if _, err := os.Stat(staged); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("staged file error = %v, want not exist", err)
	}
	// The replaced executable is not mapped here, so it unlinks immediately
	// rather than falling back to a delete on the next boot.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".old-") {
			t.Fatalf("replaced executable %s was left behind", entry.Name())
		}
	}
}

// TestWindowsInstallStagedReplacesRunningImage covers the property the whole
// design rests on: a running executable can be renamed out of the target path.
func TestWindowsInstallStagedReplacesRunningImage(t *testing.T) {
	unelevated(t)

	dir := t.TempDir()
	target := filepath.Join(dir, "running.exe")
	staged := filepath.Join(dir, "staged.exe")
	// os.Args[0] is the running test binary; copying it gives a real PE that
	// can be launched and held open while the swap happens.
	image, err := os.ReadFile(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, image, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(staged, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	running, err := os.StartProcess(target, []string{target, "-test.run=^$", "-test.timeout=30s"},
		&os.ProcAttr{Files: []*os.File{nil, nil, nil}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = running.Kill()
		_, _ = running.Wait()
	}()

	if err := installStaged(staged, target); err != nil {
		t.Fatalf("installStaged over a running image: %v", err)
	}
	contents, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != "new" {
		t.Fatalf("target contents = %q, want new", contents)
	}
}

func TestWindowsInstallStagedRestoresTargetWhenReplacementFails(t *testing.T) {
	unelevated(t)

	dir := t.TempDir()
	target := filepath.Join(dir, "gantry.exe")
	if err := os.WriteFile(target, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The staged file never exists, so moving it into place must fail after
	// the running executable has already been renamed aside.
	staged := filepath.Join(dir, "missing.exe")
	err := installStaged(staged, target)
	if err == nil {
		t.Fatal("installStaged succeeded with no staged payload")
	}
	if strings.Contains(err.Error(), "restoring") {
		t.Fatalf("installStaged failed to restore the original executable: %v", err)
	}
	contents, readErr := os.ReadFile(target)
	if readErr != nil {
		t.Fatalf("original executable was not restored: %v", readErr)
	}
	if string(contents) != "old" {
		t.Fatalf("restored contents = %q, want old", contents)
	}
}

func TestWindowsRetiredPathIsUniqueSibling(t *testing.T) {
	target := filepath.Join(t.TempDir(), "gantry.exe")
	first, err := retiredPath(target)
	if err != nil {
		t.Fatal(err)
	}
	second, err := retiredPath(target)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatalf("retiredPath is not unique: %s", first)
	}
	for _, path := range []string{first, second} {
		if filepath.Dir(path) != filepath.Dir(target) {
			t.Fatalf("retiredPath %s is not a sibling of %s", path, target)
		}
		if !strings.HasPrefix(filepath.Base(path), ".gantry.exe.old-") {
			t.Fatalf("retiredPath %s does not carry the retired prefix", path)
		}
	}
}

// TestWindowsInstallUsesNoHelperProcess guards the property this package was
// rewritten for: the update must not shell out. A helper reintroduces the
// encoded-interpreter and scheduled-task behavior that endpoint protection
// scores as a dropper installing persistence.
func TestWindowsInstallUsesNoHelperProcess(t *testing.T) {
	source, err := os.ReadFile("install_windows.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		"os/exec", "exec.Command", "powershell", "EncodedCommand",
		"ScheduledTask", "DllImport", "CREATE_BREAKAWAY_FROM_JOB",
	} {
		if strings.Contains(string(source), forbidden) {
			t.Errorf("install_windows.go reintroduced %q", forbidden)
		}
	}
}
