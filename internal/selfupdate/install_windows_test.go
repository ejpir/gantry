//go:build windows

package selfupdate

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

func TestWindowsUpdateProtectsElevatedPayload(t *testing.T) {
	old := processElevation
	processElevation = func() (bool, error) { return true, nil }
	t.Cleanup(func() { processElevation = old })

	staged := filepath.Join(t.TempDir(), "gantry.update.exe")
	if err := os.WriteFile(staged, []byte("verified"), 0o600); err != nil {
		t.Fatal(err)
	}
	elevated, err := prepareStagedUpdate(staged)
	if err != nil {
		t.Fatal(err)
	}
	if !elevated {
		t.Fatal("prepareStagedUpdate did not report elevated process")
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

	if _, err := prepareStagedUpdate("staged"); !errors.Is(err, wantErr) {
		t.Fatalf("prepareStagedUpdate elevation query error = %v, want %v", err, wantErr)
	}
}

func TestWindowsUpdateCommandReplacesTarget(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "gantry.exe")
	staged := filepath.Join(dir, "gantry update ' verified.exe")
	if err := os.WriteFile(target, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(staged, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	command, err := windowsUpdateCommand(staged, target, 0)
	if err != nil {
		t.Fatal(err)
	}
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("run Windows update process: %v: %s", err, output)
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
}

func TestWindowsDetachedUpdateReplacesAfterParentExit(t *testing.T) {
	const childEnv = "GANTRY_DETACHED_UPDATE_TEST_CHILD"
	if os.Getenv(childEnv) == "1" {
		deferred, err := installStaged(os.Getenv("GANTRY_DETACHED_UPDATE_STAGED"), os.Getenv("GANTRY_DETACHED_UPDATE_TARGET"), os.Getpid())
		if err != nil {
			t.Fatal(err)
		}
		if !deferred {
			t.Fatal("Windows update was not deferred")
		}
		return
	}

	dir := t.TempDir()
	target := filepath.Join(dir, "gantry.exe")
	staged := filepath.Join(dir, "gantry.update.exe")
	if err := os.WriteFile(target, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(staged, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	child := exec.Command(os.Args[0], "-test.run=^TestWindowsDetachedUpdateReplacesAfterParentExit$")
	child.Env = append(os.Environ(),
		childEnv+"=1",
		"GANTRY_DETACHED_UPDATE_STAGED="+staged,
		"GANTRY_DETACHED_UPDATE_TARGET="+target,
	)
	if output, err := child.CombinedOutput(); err != nil {
		t.Fatalf("run update parent: %v: %s", err, output)
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		contents, err := os.ReadFile(target)
		if err == nil && string(contents) == "new" {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	contents, err := os.ReadFile(target)
	t.Fatalf("detached update did not replace target: contents=%q err=%v", contents, err)
}

func TestUpdateScriptDoesNotInterpolatePaths(t *testing.T) {
	staged := `C:\users\me\gantry update ' staged.exe`
	target := `C:\users\me\gantry target.exe`
	script := updateScript(staged, target, 42)
	if strings.Contains(script, staged) || strings.Contains(script, target) {
		t.Fatalf("update script contains an unencoded path: %s", script)
	}
	for _, path := range []string{staged, target} {
		encoded := base64.StdEncoding.EncodeToString([]byte(path))
		if !strings.Contains(script, "'"+encoded+"'") {
			t.Fatalf("update script does not contain encoded path %q", path)
		}
	}
	if !strings.Contains(script, "$waitPid=42") {
		t.Fatalf("update script does not contain wait PID: %s", script)
	}
	if !strings.Contains(script, "MoveFileEx($staged,$target,9)") {
		t.Fatalf("update script does not use atomic replacement: %s", script)
	}
	if !strings.Contains(script, "$lock=[IO.File]::Open($staged") || !strings.Contains(script, "$lock.Dispose()") {
		t.Fatalf("update script does not lock the staged payload: %s", script)
	}
}

func TestEncodePowerShellUsesUTF16LE(t *testing.T) {
	want := "Write-Output '✓'"
	data, err := base64.StdEncoding.DecodeString(encodePowerShell(want))
	if err != nil {
		t.Fatal(err)
	}
	if len(data)%2 != 0 {
		t.Fatalf("encoded command has odd byte length %d", len(data))
	}
	units := make([]uint16, len(data)/2)
	for index := range units {
		units[index] = binary.LittleEndian.Uint16(data[index*2:])
	}
	if got := string(utf16.Decode(units)); got != want {
		t.Fatalf("decoded command = %q, want %q", got, want)
	}
}
