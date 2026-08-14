//go:build windows

package selfupdate

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

func installStaged(staged, target string, waitPID int) (bool, error) {
	helperDir := filepath.Dir(cacheFile())
	if err := os.MkdirAll(helperDir, 0o700); err != nil {
		return false, fmt.Errorf("create update helper directory: %w", err)
	}
	helper, err := os.CreateTemp(helperDir, "gantry-update-helper-*.exe")
	if err != nil {
		return false, fmt.Errorf("create update helper: %w", err)
	}
	helperPath := helper.Name()
	cleanup := true
	defer func() {
		_ = helper.Close()
		if cleanup {
			_ = os.Remove(helperPath)
		}
	}()
	source, err := os.Open(staged)
	if err != nil {
		return false, fmt.Errorf("open staged update: %w", err)
	}
	if _, err := io.Copy(helper, source); err != nil {
		_ = source.Close()
		return false, fmt.Errorf("copy update helper: %w", err)
	}
	if err := source.Close(); err != nil {
		return false, fmt.Errorf("close staged update: %w", err)
	}
	if err := helper.Sync(); err != nil {
		return false, fmt.Errorf("sync update helper: %w", err)
	}
	if err := helper.Close(); err != nil {
		return false, fmt.Errorf("close update helper: %w", err)
	}
	if waitPID <= 0 {
		waitPID = os.Getpid()
	}
	command := exec.Command(helperPath, "_finish-update",
		"--target", target, "--staged", staged, "--wait-pid", strconv.Itoa(waitPID))
	command.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP | 0x00000008, // DETACHED_PROCESS
		HideWindow:    true,
	}
	if err := command.Start(); err != nil {
		return false, fmt.Errorf("start update helper: %w", err)
	}
	cleanup = false
	// Once Start succeeds the helper owns staged. A Release failure must not
	// make the caller delete the file out from under that running helper.
	_ = command.Process.Release()
	return true, nil
}

// Finish waits for the process using the old executable to leave, then moves
// the verified staged binary into place. It runs in a detached helper copy so
// neither the old nor new target is the executing image.
func Finish(target, staged string, waitPID int) error {
	if target == "" || staged == "" {
		return fmt.Errorf("update helper requires target and staged paths")
	}
	if waitPID > 0 {
		process, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(waitPID))
		if err == nil {
			_, _ = windows.WaitForSingleObject(process, windows.INFINITE)
			_ = windows.CloseHandle(process)
		}
	}
	from, err := windows.UTF16PtrFromString(staged)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(time.Minute)
	for {
		err = windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
		if err == nil {
			break
		}
		if (!errors.Is(err, windows.ERROR_ACCESS_DENIED) && !errors.Is(err, windows.ERROR_SHARING_VIOLATION)) || time.Now().After(deadline) {
			return fmt.Errorf("finish Gantry update: %w", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	// Windows cannot unlink the executing helper. Scheduling deletion at the
	// next reboot prevents helper copies from accumulating indefinitely.
	helper, helperErr := os.Executable()
	if helperErr == nil {
		if helperPath, pathErr := windows.UTF16PtrFromString(helper); pathErr == nil {
			_ = windows.MoveFileEx(helperPath, nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT)
		}
	}
	return nil
}
