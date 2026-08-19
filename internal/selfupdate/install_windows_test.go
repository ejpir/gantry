//go:build windows

package selfupdate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

const (
	windowsRunningImageHelperEnv   = "GANTRY_TEST_RUNNING_IMAGE_HELPER"
	windowsRunningImageReadyEnv    = "GANTRY_TEST_RUNNING_IMAGE_READY"
	windowsRunningImageHelperValue = "1"
)

func TestWindowsRunningImageHelper(t *testing.T) {
	if os.Getenv(windowsRunningImageHelperEnv) != windowsRunningImageHelperValue {
		return
	}
	ready := os.Getenv(windowsRunningImageReadyEnv)
	if ready == "" {
		t.Fatal("running-image helper has no readiness path")
	}
	if err := os.WriteFile(ready, []byte("ready"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Keep this copied test image mapped until the parent terminates us. A
	// sleep, rather than an empty select, also keeps the runtime's deadlock
	// detector from mistaking the helper for a stuck test process.
	for {
		time.Sleep(time.Hour)
	}
}

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

	target := filepath.Join(t.TempDir(), "gantry.exe")
	file, err := createStagedFile(target)
	if err != nil {
		t.Fatal(err)
	}
	staged := file.Name()
	if err := file.Close(); err != nil {
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
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	if !owner.Equals(user.User.Sid) {
		t.Fatalf("staged update owner = %s, want %s", owner, user.User.Sid)
	}
	control, _, err := descriptor.Control()
	if err != nil {
		t.Fatal(err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatalf("staged update DACL control = %#x, want SE_DACL_PROTECTED", control)
	}
	world, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(descriptor.String(), world.String()) {
		t.Fatalf("protected staged update grants Everyone access: %s", descriptor)
	}
}

func TestWindowsUpdateFailsClosedWhenElevationQueryFails(t *testing.T) {
	old := processElevation
	wantErr := errors.New("token query failed")
	processElevation = func() (bool, error) { return false, wantErr }
	t.Cleanup(func() { processElevation = old })

	if _, err := createStagedFile(filepath.Join(t.TempDir(), "target.exe")); !errors.Is(err, wantErr) {
		t.Fatalf("createStagedFile elevation query error = %v, want %v", err, wantErr)
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
	if err := installStaged(context.Background(), staged, target); err != nil {
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
// design rests on: ReplaceFileW can back up a currently mapped executable.
func TestWindowsInstallStagedReplacesRunningImage(t *testing.T) {
	unelevated(t)

	dir := t.TempDir()
	target := filepath.Join(dir, "running.exe")
	staged := filepath.Join(dir, "staged.exe")
	ready := filepath.Join(dir, "running.ready")
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
	running, err := os.StartProcess(target, []string{
		target,
		"-test.run=^TestWindowsRunningImageHelper$",
		"-test.timeout=30s",
	}, &os.ProcAttr{
		Files: []*os.File{nil, nil, nil},
		Env: append(os.Environ(),
			windowsRunningImageHelperEnv+"="+windowsRunningImageHelperValue,
			windowsRunningImageReadyEnv+"="+ready,
		),
	})
	if err != nil {
		t.Fatal(err)
	}
	childDone := make(chan struct{})
	var waitErr error
	go func() {
		_, waitErr = running.Wait()
		close(childDone)
	}()
	t.Cleanup(func() {
		_ = running.Kill()
		select {
		case <-childDone:
		case <-time.After(5 * time.Second):
			t.Error("running-image helper did not exit after Kill")
		}
	})

	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	poll := time.NewTicker(10 * time.Millisecond)
	defer poll.Stop()
waitReady:
	for {
		if _, statErr := os.Stat(ready); statErr == nil {
			break waitReady
		} else if !errors.Is(statErr, os.ErrNotExist) {
			t.Fatal(statErr)
		}
		select {
		case <-childDone:
			t.Fatalf("running-image helper exited before readiness: %v", waitErr)
		case <-poll.C:
		case <-deadline.C:
			t.Fatal("timed out waiting for running-image helper readiness")
		}
	}
	select {
	case <-childDone:
		t.Fatalf("running-image helper exited before replacement: %v", waitErr)
	default:
	}

	if err := installStaged(context.Background(), staged, target); err != nil {
		t.Fatalf("installStaged over a running image: %v", err)
	}
	select {
	case <-childDone:
		t.Fatalf("replacement terminated the running image: %v", waitErr)
	default:
	}
	contents, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != "new" {
		t.Fatalf("target contents = %q, want new", contents)
	}
	if err := running.Kill(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-childDone:
	case <-time.After(5 * time.Second):
		t.Fatal("running-image helper did not exit before cleanup")
	}
	if err := cleanupRetired(target); err != nil {
		t.Fatalf("cleanup retired running image: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), retiredPrefix(target)) {
			t.Fatalf("retired running image %s survived next-invocation cleanup", entry.Name())
		}
	}
}

func TestWindowsInstallStagedKeepsTargetWhenReplacementFails(t *testing.T) {
	unelevated(t)

	dir := t.TempDir()
	target := filepath.Join(dir, "gantry.exe")
	if err := os.WriteFile(target, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	// ReplaceFileW fails before changing either name when the replacement does
	// not exist; the original canonical target must remain intact.
	staged := filepath.Join(dir, "missing.exe")
	err := installStaged(context.Background(), staged, target)
	if err == nil {
		t.Fatal("installStaged succeeded with no staged payload")
	}
	contents, readErr := os.ReadFile(target)
	if readErr != nil {
		t.Fatalf("original executable was not restored: %v", readErr)
	}
	if string(contents) != "old" {
		t.Fatalf("restored contents = %q, want old", contents)
	}
}

func TestWindowsInstallRetriesSharingViolation(t *testing.T) {
	unelevated(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "gantry.exe")
	staged := filepath.Join(dir, "staged.exe")
	if err := os.WriteFile(target, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(staged, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	oldReplace := replaceFile
	attempts := 0
	replaceFile = func(target, staged, retired string) error {
		attempts++
		if attempts == 1 {
			return windows.ERROR_SHARING_VIOLATION
		}
		return replaceFilePath(target, staged, retired)
	}
	t.Cleanup(func() { replaceFile = oldReplace })

	if err := installStaged(context.Background(), staged, target); err != nil {
		t.Fatal(err)
	}
	if attempts != 2 {
		t.Fatalf("ReplaceFileW attempts = %d, want 2", attempts)
	}
	if got, err := os.ReadFile(target); err != nil || string(got) != "new" {
		t.Fatalf("replacement contents = %q, err=%v", got, err)
	}
}

func TestWindowsInstallRestoresDocumentedPartialReplacement(t *testing.T) {
	unelevated(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "gantry.exe")
	staged := filepath.Join(dir, "staged.exe")
	if err := os.WriteFile(target, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(staged, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	oldReplace := replaceFile
	replaceFile = func(target, _ string, retired string) error {
		if err := moveFilePath(target, retired, windows.MOVEFILE_REPLACE_EXISTING); err != nil {
			return err
		}
		return windows.ERROR_UNABLE_TO_MOVE_REPLACEMENT_2
	}
	t.Cleanup(func() { replaceFile = oldReplace })

	err := installStaged(context.Background(), staged, target)
	if !errors.Is(err, windows.ERROR_UNABLE_TO_MOVE_REPLACEMENT_2) {
		t.Fatalf("partial replacement error = %v", err)
	}
	if got, readErr := os.ReadFile(target); readErr != nil || string(got) != "old" {
		t.Fatalf("restored target = %q, err=%v", got, readErr)
	}
}

func TestWindowsInstallPreservesTargetDACL(t *testing.T) {
	unelevated(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "gantry.exe")
	staged := filepath.Join(dir, "staged.exe")
	if err := os.WriteFile(target, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(staged, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	desired, err := windows.SecurityDescriptorFromString(
		"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + user.User.Sid.String() + ")(A;;GRGX;;;BU)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := desired.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(target, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	before, err := windows.GetNamedSecurityInfo(target, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}

	if err := installStaged(context.Background(), staged, target); err != nil {
		t.Fatal(err)
	}
	after, err := windows.GetNamedSecurityInfo(target, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if before.String() != after.String() {
		t.Fatalf("target DACL changed:\nbefore: %s\nafter:  %s", before, after)
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
