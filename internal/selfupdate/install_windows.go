//go:build windows

package selfupdate

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const elevatedUpdateMessage = "windows self-update is disabled for elevated processes; run Gantry unelevated from a user-writable installation or replace the binary manually"

var processElevation = currentProcessElevation

func installStaged(staged, target string, waitPID int) (bool, error) {
	if err := requireUnelevatedProcess(); err != nil {
		return false, err
	}
	// stageBinary has already proved that target's directory is writable and
	// placed the verified payload there. Keep the helper in the same directory
	// instead of crossing into user cache, which may have weaker permissions
	// than an installation directory.
	helper, helperPath, err := createLockedUpdateHelper(filepath.Dir(target))
	if err != nil {
		return false, fmt.Errorf("create update helper: %w", err)
	}
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
	// createLockedUpdateHelper denies concurrent write and delete opens. Keep
	// that handle alive through CreateProcess so the path cannot be replaced
	// between verification/copy and image mapping.
	cleanup = false
	_ = helper.Close()
	// Once Start succeeds the helper owns staged. A Release failure must not
	// make the caller delete the file out from under that running helper.
	_ = command.Process.Release()
	return true, nil
}

// createLockedUpdateHelper creates a random file without sharing write or
// delete access. os.CreateTemp on Windows shares writes, which permits a
// same-user process to modify a helper while its creator still has it open.
func createLockedUpdateHelper(dir string) (*os.File, string, error) {
	for range 32 {
		var entropy [16]byte
		if _, err := rand.Read(entropy[:]); err != nil {
			return nil, "", fmt.Errorf("generate helper name: %w", err)
		}
		path := filepath.Join(dir, ".gantry-update-helper-"+hex.EncodeToString(entropy[:])+".exe")
		pathPtr, err := windows.UTF16PtrFromString(path)
		if err != nil {
			return nil, "", err
		}
		handle, err := windows.CreateFile(
			pathPtr,
			windows.GENERIC_READ|windows.GENERIC_WRITE,
			windows.FILE_SHARE_READ,
			nil,
			windows.CREATE_NEW,
			windows.FILE_ATTRIBUTE_NORMAL,
			0,
		)
		if errors.Is(err, windows.ERROR_FILE_EXISTS) || errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			continue
		}
		if err != nil {
			return nil, "", err
		}
		return os.NewFile(uintptr(handle), path), path, nil
	}
	return nil, "", fmt.Errorf("allocate unique update helper name")
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

// Finish waits for the process using the old executable to leave, then moves
// the verified staged binary into place. It runs in a detached helper copy so
// neither the old nor new target is the executing image.
func Finish(target, staged string, waitPID int) error {
	if err := requireUnelevatedProcess(); err != nil {
		return err
	}
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
