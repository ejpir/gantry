package vmmworker

import (
	"fmt"
	"os"

	"github.com/ejpir/gantry/internal/gutil"
	"golang.org/x/sys/windows"
)

func lockDiskForRelay(source *os.File) (*os.File, error) {
	private, err := duplicateDiskFile(source)
	if err != nil {
		return nil, err
	}
	if _, err := gutil.TryLockFD(private); err != nil {
		_ = private.Close()
		return nil, err
	}
	return private, nil
}

func duplicateDiskFile(source *os.File) (*os.File, error) {
	process := windows.CurrentProcess()
	var duplicate windows.Handle
	if err := windows.DuplicateHandle(process, windows.Handle(source.Fd()), process, &duplicate, 0, false, windows.DUPLICATE_SAME_ACCESS); err != nil {
		return nil, fmt.Errorf("duplicate writable disk %s: %w", source.Name(), err)
	}
	file := os.NewFile(uintptr(duplicate), source.Name()+" (broker)")
	if file == nil {
		_ = windows.CloseHandle(duplicate)
		return nil, fmt.Errorf("duplicate writable disk %s: invalid handle", source.Name())
	}
	return file, nil
}
