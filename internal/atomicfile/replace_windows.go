//go:build windows

package atomicfile

import (
	"os"

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
	return windows.MoveFileEx(fromPath, toPath, flags)
}

// MOVEFILE_WRITE_THROUGH flushes the replacement on Windows. Opening a
// directory for fsync requires backup-semantics handles and adds no guarantee
// beyond that flag.
func syncParent(string) error { return nil }
