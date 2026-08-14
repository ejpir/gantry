//go:build windows

package selfupdate

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsUpdateRejectsElevatedProcess(t *testing.T) {
	old := processElevation
	processElevation = func() (bool, error) { return true, nil }
	t.Cleanup(func() { processElevation = old })

	if _, err := installStaged("staged", "target", 0); err == nil || !strings.Contains(err.Error(), "disabled for elevated") {
		t.Fatalf("installStaged elevated error = %v", err)
	}
	if err := Finish("target", "staged", 0); err == nil || !strings.Contains(err.Error(), "disabled for elevated") {
		t.Fatalf("Finish elevated error = %v", err)
	}
}

func TestWindowsUpdateFailsClosedWhenElevationQueryFails(t *testing.T) {
	old := processElevation
	wantErr := errors.New("token query failed")
	processElevation = func() (bool, error) { return false, wantErr }
	t.Cleanup(func() { processElevation = old })

	if _, err := installStaged("staged", "target", 0); !errors.Is(err, wantErr) {
		t.Fatalf("installStaged elevation query error = %v, want %v", err, wantErr)
	}
	if err := Finish("target", "staged", 0); !errors.Is(err, wantErr) {
		t.Fatalf("Finish elevation query error = %v, want %v", err, wantErr)
	}
}

func TestLockedUpdateHelperUsesTargetDirectoryAndDeniesMutation(t *testing.T) {
	dir := t.TempDir()
	helper, path, err := createLockedUpdateHelper(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = helper.Close()
		_ = os.Remove(path)
	}()
	if filepath.Dir(path) != dir {
		t.Fatalf("helper directory = %q, want %q", filepath.Dir(path), dir)
	}

	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := windows.CreateFile(
		pathPtr,
		windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err == nil {
		_ = windows.CloseHandle(second)
		t.Fatal("second writer opened locked update helper")
	}
	if !errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
		t.Fatalf("second writer error = %v, want sharing violation", err)
	}
	if err := os.Remove(path); !errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
		t.Fatalf("remove locked helper error = %v, want sharing violation", err)
	}
}

func TestLockedUpdateHelperCanStartWhileHeld(t *testing.T) {
	if os.Getenv("GANTRY_LOCKED_HELPER_CHILD") == "1" {
		return
	}
	dir := t.TempDir()
	helper, path, err := createLockedUpdateHelper(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = helper.Close()
		_ = os.Remove(path)
	}()
	source, err := os.Open(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(helper, source); err != nil {
		_ = source.Close()
		t.Fatal(err)
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	if err := helper.Sync(); err != nil {
		t.Fatal(err)
	}

	command := exec.Command(path, "-test.run=^TestLockedUpdateHelperCanStartWhileHeld$")
	command.Env = append(os.Environ(), "GANTRY_LOCKED_HELPER_CHILD=1")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("start locked helper: %v: %s", err, output)
	}
}
