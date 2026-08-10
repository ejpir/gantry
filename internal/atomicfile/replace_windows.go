//go:build windows

package atomicfile

import "golang.org/x/sys/windows"

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
