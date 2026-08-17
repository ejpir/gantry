//go:build windows

package selfupdate

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

const protectedUpdateSDDL = "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)"

var (
	processElevation = currentProcessElevation
	systemDirectory  = windows.GetSystemDirectory
)

func installStaged(staged, target string, waitPID int) (bool, error) {
	elevated, err := prepareStagedUpdate(staged)
	if err != nil {
		return false, err
	}
	if waitPID <= 0 {
		waitPID = os.Getpid()
	}
	command, err := windowsUpdateCommand(staged, target, waitPID)
	if err != nil {
		return false, err
	}
	if elevated {
		command, err = windowsScheduledUpdateCommand(command)
		if err != nil {
			return false, err
		}
		if output, err := command.CombinedOutput(); err != nil {
			return false, fmt.Errorf("schedule elevated Windows update: %w: %s", err, output)
		}
		return true, nil
	}
	command.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP | 0x00000008 | // DETACHED_PROCESS
			windows.CREATE_BREAKAWAY_FROM_JOB,
		HideWindow: true,
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

// windowsScheduledUpdateCommand turns the elevated helper into a one-shot
// Task Scheduler action. Service managers (including SSM Run Command) can
// place callers in a kill-on-close job, which also kills an ordinary detached
// descendant when the command returns. Task Scheduler creates the updater in
// its own service context, outside that caller-owned job. The registration
// process waits until the action is running and then removes the task; deleting
// a running task does not terminate its action.
func windowsScheduledUpdateCommand(helper *exec.Cmd) (*exec.Cmd, error) {
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return nil, fmt.Errorf("name elevated Windows update task: %w", err)
	}
	taskName := "Gantry-SelfUpdate-" + hex.EncodeToString(suffix[:])
	systemDir, err := systemDirectory()
	if err != nil {
		return nil, fmt.Errorf("locate Windows system directory: %w", err)
	}
	powerShell := filepath.Join(systemDir, "WindowsPowerShell", "v1.0", "powershell.exe")
	if len(helper.Args) == 0 || !strings.EqualFold(helper.Args[0], powerShell) {
		return nil, fmt.Errorf("invalid elevated Windows update helper")
	}
	helperArgs := strings.Join(helper.Args[1:], " ")
	script := scheduledUpdateScript(powerShell, helperArgs, taskName)
	command := exec.Command(powerShell,
		"-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
		"-EncodedCommand", encodePowerShell(script),
	)
	command.Dir = systemDir
	return command, nil
}

func scheduledUpdateScript(powerShell, helperArgs, taskName string) string {
	decode := func(value string) string {
		return "[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" +
			base64.StdEncoding.EncodeToString([]byte(value)) + "'))"
	}
	return `$ErrorActionPreference='Stop'
$powerShell=` + decode(powerShell) + `
$arguments=` + decode(helperArgs) + `
$taskName=` + decode(taskName) + `
$action=New-ScheduledTaskAction -Execute $powerShell -Argument $arguments
$principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 2) -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings -Force | Out-Null
try {
  Start-ScheduledTask -TaskName $taskName
  $deadline=[DateTime]::UtcNow.AddSeconds(10)
  while ((Get-ScheduledTask -TaskName $taskName).State -ne 'Running') {
    if ([DateTime]::UtcNow -ge $deadline) { throw 'elevated update task did not start' }
    Start-Sleep -Milliseconds 10
  }
} catch {
  Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
  throw
}
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
`
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
$lock=[IO.File]::Open($staged,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
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
$lock.Dispose()
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

// prepareStagedUpdate closes the privilege boundary that originally required
// all elevated Windows updates to be rejected. The verified payload is owned
// by Administrators, gets a protected SYSTEM/Administrators-only DACL, and is
// held without write/delete sharing by the detached helper until replacement.
// Unelevated installs retain their user-owned ACL so the same user can finish
// the update normally.
func prepareStagedUpdate(staged string) (bool, error) {
	elevated, err := processElevation()
	if err != nil {
		return false, err
	}
	if !elevated {
		return false, nil
	}
	descriptor, err := windows.SecurityDescriptorFromString(protectedUpdateSDDL)
	if err != nil {
		return false, fmt.Errorf("build protected update permissions: %w", err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		return false, fmt.Errorf("read protected update owner: %w", err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return false, fmt.Errorf("read protected update permissions: %w", err)
	}
	securityInformation := windows.SECURITY_INFORMATION(windows.OWNER_SECURITY_INFORMATION |
		windows.DACL_SECURITY_INFORMATION |
		windows.PROTECTED_DACL_SECURITY_INFORMATION)
	if err := windows.SetNamedSecurityInfo(
		staged, windows.SE_FILE_OBJECT, securityInformation, owner, nil, dacl, nil,
	); err != nil {
		return false, fmt.Errorf("protect elevated staged update: %w", err)
	}
	return true, nil
}
