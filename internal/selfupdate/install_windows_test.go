//go:build windows

package selfupdate

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"
)

func TestWindowsUpdateRejectsElevatedProcess(t *testing.T) {
	old := processElevation
	processElevation = func() (bool, error) { return true, nil }
	t.Cleanup(func() { processElevation = old })

	if _, err := installStaged("staged", "target", 0); err == nil || !strings.Contains(err.Error(), "disabled for elevated") {
		t.Fatalf("installStaged elevated error = %v", err)
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
