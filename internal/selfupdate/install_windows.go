//go:build windows

package selfupdate

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

const elevatedUpdateMessage = "windows self-update is disabled for elevated processes; run Gantry unelevated from a user-writable installation or replace the binary manually"

var (
	processElevation = currentProcessElevation
	systemDirectory  = windows.GetSystemDirectory
)

func installStaged(staged, target string, waitPID int) (bool, error) {
	if err := requireUnelevatedProcess(); err != nil {
		return false, err
	}
	if waitPID <= 0 {
		waitPID = os.Getpid()
	}
	command, err := windowsUpdateCommand(staged, target, waitPID)
	if err != nil {
		return false, err
	}
	command.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP | 0x00000008, // DETACHED_PROCESS
		HideWindow:    true,
	}
	if err := command.Start(); err != nil {
		return false, fmt.Errorf("start Windows update process: %w", err)
	}
	// Once Start succeeds the detached process owns staged. A Release failure
	// must not make the caller delete the file out from under that process.
	_ = command.Process.Release()
	return true, nil
}

func windowsUpdateCommand(staged, target string, waitPID int) (*exec.Cmd, error) {
	systemDir, err := systemDirectory()
	if err != nil {
		return nil, fmt.Errorf("locate Windows system directory: %w", err)
	}
	powerShell := filepath.Join(systemDir, "WindowsPowerShell", "v1.0", "powershell.exe")
	if info, err := os.Stat(powerShell); err != nil {
		return nil, fmt.Errorf("locate Windows PowerShell: %w", err)
	} else if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("windows PowerShell path is not a regular file: %s", powerShell)
	}
	command := exec.Command(powerShell,
		"-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
		"-EncodedCommand", encodePowerShell(updateScript(staged, target, waitPID)),
	)
	// Keep native DLL and executable lookup away from caller-controlled working
	// directories. The executable itself is also addressed by its absolute path.
	command.Dir = systemDir
	return command, nil
}

func updateScript(staged, target string, waitPID int) string {
	// The path values are base64-encoded separately, so no path characters can
	// become PowerShell syntax. waitPID is formatted as a decimal integer.
	staged64 := base64.StdEncoding.EncodeToString([]byte(staged))
	target64 := base64.StdEncoding.EncodeToString([]byte(target))
	return `$ErrorActionPreference='Stop'
$staged=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('` + staged64 + `'))
$target=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('` + target64 + `'))
$waitPid=` + strconv.Itoa(waitPID) + `
Add-Type -TypeDefinition @'
using System.Runtime.InteropServices;
public static class GantryUpdate {
  [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  public static extern bool MoveFileEx(string existing, string replacement, uint flags);
}
'@
if ($waitPid -gt 0) {
  try {
    $process=[Diagnostics.Process]::GetProcessById($waitPid)
    $process.WaitForExit()
    $process.Dispose()
  } catch [ArgumentException] {}
}
$deadline=[DateTime]::UtcNow.AddMinutes(1)
while ($true) {
  if ([GantryUpdate]::MoveFileEx($staged,$target,9)) {
    exit 0
  }
  $errorCode=[Runtime.InteropServices.Marshal]::GetLastWin32Error()
  if (($errorCode -ne 5) -and ($errorCode -ne 32)) {
    [Console]::Error.WriteLine("MoveFileEx failed with Windows error $errorCode")
    exit 1
  }
  if ([DateTime]::UtcNow -ge $deadline) {
    [Console]::Error.WriteLine("MoveFileEx timed out with Windows error $errorCode")
    exit 1
  }
  Start-Sleep -Milliseconds 50
}`
}

func encodePowerShell(script string) string {
	units := utf16.Encode([]rune(script))
	encoded := make([]byte, len(units)*2)
	for index, unit := range units {
		binary.LittleEndian.PutUint16(encoded[index*2:], unit)
	}
	return base64.StdEncoding.EncodeToString(encoded)
}

func currentProcessElevation() (bool, error) {
	var elevated uint32
	var outputSize uint32
	err := windows.GetTokenInformation(
		windows.GetCurrentProcessToken(),
		windows.TokenElevation,
		(*byte)(unsafe.Pointer(&elevated)),
		uint32(unsafe.Sizeof(elevated)),
		&outputSize,
	)
	if err != nil {
		return false, fmt.Errorf("query process elevation: %w", err)
	}
	if outputSize != uint32(unsafe.Sizeof(elevated)) {
		return false, fmt.Errorf("query process elevation: unexpected result size %d", outputSize)
	}
	return elevated != 0, nil
}

func requireUnelevatedProcess() error {
	elevated, err := processElevation()
	if err != nil {
		return err
	}
	if elevated {
		return errors.New(elevatedUpdateMessage)
	}
	return nil
}
