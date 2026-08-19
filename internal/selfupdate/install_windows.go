//go:build windows

package selfupdate

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	replaceRetryTimeout  = time.Minute
	replaceRetryInitial  = 50 * time.Millisecond
	replaceRetryMaximum  = time.Second
	retiredSuffixHexSize = 16
)

var (
	procReplaceFile = windows.NewLazySystemDLL("kernel32.dll").NewProc("ReplaceFileW")
	replaceFile     = replaceFilePath
	moveFile        = windows.MoveFileEx
)

// installStaged replaces the executable with one ReplaceFileW operation.
// Supplying a backup name lets Windows rename a currently mapped image while
// preserving the target's ACL, attributes, and alternate streams. Crucially,
// user code never exposes the canonical target name between two operations.
func installStaged(ctx context.Context, staged, target string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	// A prior process can leave its old image mapped. It is safe to retry that
	// cleanup now, but a still-running old process must not block this update.
	_ = cleanupRetired(target)
	retired, err := retiredPath(target)
	if err != nil {
		return err
	}

	retryCtx, cancel := context.WithTimeout(ctx, replaceRetryTimeout)
	defer cancel()
	delay := replaceRetryInitial
	for {
		err = replaceFile(target, staged, retired)
		if err == nil {
			discardRetired(retired)
			return nil
		}
		if errors.Is(err, windows.ERROR_UNABLE_TO_MOVE_REPLACEMENT_2) {
			// ReplaceFileW documents this as its one partial state: the old
			// target reached the backup name but the replacement did not reach
			// target. Restore the verified old image over any path occupant.
			if restoreErr := restorePartialReplacement(retired, target); restoreErr != nil {
				return fmt.Errorf("replace Gantry executable %s: %w (restore %s: %v)",
					target, err, retired, restoreErr)
			}
			return fmt.Errorf("replace Gantry executable %s: %w", target, err)
		}
		if !replaceRetryable(err) {
			return fmt.Errorf("replace Gantry executable %s: %w", target, err)
		}

		timer := time.NewTimer(delay)
		select {
		case <-timer.C:
			if delay < replaceRetryMaximum {
				delay = min(delay*2, replaceRetryMaximum)
			}
		case <-retryCtx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return fmt.Errorf("replace Gantry executable %s after transient error %v: %w",
				target, err, retryCtx.Err())
		}
	}
}

func replaceRetryable(err error) bool {
	return errors.Is(err, windows.ERROR_SHARING_VIOLATION) ||
		errors.Is(err, windows.ERROR_ACCESS_DENIED)
}

func replaceFilePath(target, staged, retired string) error {
	target16, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return fmt.Errorf("invalid target path %q: %w", target, err)
	}
	staged16, err := windows.UTF16PtrFromString(staged)
	if err != nil {
		return fmt.Errorf("invalid staged path %q: %w", staged, err)
	}
	retired16, err := windows.UTF16PtrFromString(retired)
	if err != nil {
		return fmt.Errorf("invalid backup path %q: %w", retired, err)
	}
	result, _, callErr := procReplaceFile.Call(
		uintptr(unsafe.Pointer(target16)),
		uintptr(unsafe.Pointer(staged16)),
		uintptr(unsafe.Pointer(retired16)),
		0, // preserve every mergeable target attribute and stream
		0,
		0,
	)
	if result != 0 {
		return nil
	}
	if callErr != nil && !errors.Is(callErr, windows.ERROR_SUCCESS) {
		return callErr
	}
	return syscall.EINVAL
}

func restorePartialReplacement(retired, target string) error {
	if _, err := os.Stat(retired); err != nil {
		return fmt.Errorf("locate replacement backup: %w", err)
	}
	return moveFilePath(retired, target,
		windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

// retiredPath names ReplaceFileW's backup. The random suffix keeps concurrent
// or interrupted updates from colliding.
func retiredPath(target string) (string, error) {
	var suffix [retiredSuffixHexSize / 2]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return "", fmt.Errorf("name replaced Gantry executable: %w", err)
	}
	return filepath.Join(filepath.Dir(target), retiredPrefix(target)+hex.EncodeToString(suffix[:])), nil
}

func retiredPrefix(target string) string {
	return "." + filepath.Base(target) + ".old-"
}

// discardRetired succeeds immediately for an idle target. A mapped executable
// remains until its process exits; cleanupRetired removes it on a later Gantry
// invocation without relying on the privileged delayed-reboot mechanism.
func discardRetired(retired string) {
	_ = os.Remove(retired)
}

func cleanupRetired(target string) error {
	entries, err := os.ReadDir(filepath.Dir(target))
	if err != nil {
		return err
	}
	prefix := retiredPrefix(target)
	var cleanupErr error
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasPrefix(name, prefix) {
			continue
		}
		suffix := strings.TrimPrefix(name, prefix)
		if len(suffix) != retiredSuffixHexSize {
			continue
		}
		if _, err := hex.DecodeString(suffix); err != nil {
			continue
		}
		path := filepath.Join(filepath.Dir(target), name)
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("remove retired executable %s: %w", path, err))
		}
	}
	return cleanupErr
}

func moveFilePath(from, to string, flags uint32) error {
	source, err := windows.UTF16PtrFromString(from)
	if err != nil {
		return fmt.Errorf("invalid path %q: %w", from, err)
	}
	destination, err := windows.UTF16PtrFromString(to)
	if err != nil {
		return fmt.Errorf("invalid path %q: %w", to, err)
	}
	return moveFile(source, destination, flags)
}
