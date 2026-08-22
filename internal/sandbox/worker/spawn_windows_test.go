package worker

import (
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsWorkersDoNotAllocateConsoleWindows(t *testing.T) {
	attr := WindowsSysProcAttr(0, nil)
	if attr.CreationFlags&windows.CREATE_NO_WINDOW == 0 {
		t.Fatalf("worker creation flags %#x omit CREATE_NO_WINDOW", attr.CreationFlags)
	}
}
