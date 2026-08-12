//go:build windows

package atomicfile

import (
	"errors"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

// FlushFileBuffers (used by os.File.Sync) requires a handle opened for
// writing on Windows. os.Open's read-only handle fails with ACCESS_DENIED.
func openCommittedForSync(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDWR, 0)
}

func replace(from, to string, durable bool) error {
	fromPath, err := windows.UTF16PtrFromString(from)
	if err != nil {
		return err
	}
	toPath, err := windows.UTF16PtrFromString(to)
	if err != nil {
		return err
	}
	flags := uint32(windows.MOVEFILE_REPLACE_EXISTING)
	if durable {
		flags |= windows.MOVEFILE_WRITE_THROUGH
	}
	// MoveFileEx can transiently return ACCESS_DENIED or SHARING_VIOLATION
	// when another writer is replacing the same destination. The temporary
	// file is already closed, so retrying preserves the same atomic commit
	// point and lets independent configuration writers serialize in-kernel.
	deadline := time.Now().Add(time.Second)
	delay := time.Millisecond
	for {
		err := windows.MoveFileEx(fromPath, toPath, flags)
		if err == nil {
			return nil
		}
		if !errors.Is(err, windows.ERROR_ACCESS_DENIED) && !errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
			return err
		}
		if time.Now().After(deadline) {
			return err
		}
		time.Sleep(delay)
		if delay < 10*time.Millisecond {
			delay *= 2
		}
	}
}

// MOVEFILE_WRITE_THROUGH flushes the replacement on Windows. Opening a
// directory for fsync requires backup-semantics handles and adds no guarantee
// beyond that flag.
func syncParent(string) error { return nil }
