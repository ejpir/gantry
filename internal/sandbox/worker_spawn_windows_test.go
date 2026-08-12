package sandbox

import (
	"slices"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsWorkersDoNotAllocateConsoleWindows(t *testing.T) {
	attr := windowsWorkerSysProcAttr(0, nil)
	if attr.CreationFlags&windows.CREATE_NO_WINDOW == 0 {
		t.Fatalf("worker creation flags %#x omit CREATE_NO_WINDOW", attr.CreationFlags)
	}
}

func TestWindowsWorkerEnvironmentIsAnExplicitAllowlist(t *testing.T) {
	for _, key := range []string{
		"SystemRoot", "WINDIR", "SystemDrive", "TEMP", "TMP",
		"GANTRY_DEBUG_RTC", "GANTRY_PREFAULT_RAM", "GANTRY_BOOT_PROFILE",
		"GANTRY_WHPX_PIC", "GANTRY_WHPX_PIC_NOPIT",
	} {
		t.Setenv(key, "")
	}
	t.Setenv("PATH", `C:\host-tools`)
	t.Setenv("HOME", `C:\host-home`)
	t.Setenv("GANTRY_SECRET_TEST", "must-not-cross")
	t.Setenv("SystemRoot", `C:\Windows`)
	t.Setenv("TEMP", `C:\Temp`)
	t.Setenv("GANTRY_BOOT_PROFILE", "1")
	t.Setenv("GANTRY_WHPX_PIC", "enabled")
	t.Setenv("GANTRY_WHPX_PIC_NOPIT", "enabled")

	want := []string{
		`SystemRoot=C:\Windows`, `TEMP=C:\Temp`, "GANTRY_BOOT_PROFILE=1",
		"GANTRY_WHPX_PIC=1", "GANTRY_WHPX_PIC_NOPIT=1",
	}
	if got := workerEnv(); !slices.Equal(got, want) {
		t.Fatalf("worker environment = %v, want %v", got, want)
	}
}
