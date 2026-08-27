package vmmworker

import (
	"slices"
	"testing"

	"github.com/ejpir/gantry/internal/sandbox/config"
)

func TestWindowsVMMEnvironmentIsAnExplicitAllowlist(t *testing.T) {
	for _, key := range []string{
		"SystemRoot", "WINDIR", "SystemDrive", "TEMP", "TMP",
		"GANTRY_DEBUG_RTC", "GANTRY_PREFAULT_RAM", "GANTRY_BOOT_PROFILE", "GANTRY_VHOST_STATS",
		"GANTRY_VIRTIO_MEM", "GANTRY_WHPX_PIC", "GANTRY_WHPX_PIC_NOPIT",
	} {
		t.Setenv(key, "")
	}
	t.Setenv("PATH", `C:\host-tools`)
	t.Setenv("HOME", `C:\host-home`)
	t.Setenv("GANTRY_SECRET_TEST", "must-not-cross")
	t.Setenv("SystemRoot", `C:\Windows`)
	t.Setenv("TEMP", `C:\Temp`)
	t.Setenv("GANTRY_BOOT_PROFILE", "1")
	t.Setenv("GANTRY_VHOST_STATS", "1")
	t.Setenv("GANTRY_VIRTIO_MEM", "on")
	t.Setenv("GANTRY_WHPX_PIC", "enabled")
	t.Setenv("GANTRY_WHPX_PIC_NOPIT", "enabled")

	want := []string{
		`SystemRoot=C:\Windows`, "GANTRY_BOOT_PROFILE=1", "GANTRY_VHOST_STATS=1",
		"GANTRY_VIRTIO_MEM=1", "GANTRY_WHPX_PIC=1", "GANTRY_WHPX_PIC_NOPIT=1",
	}
	if got := vmmWorkerEnv(); !slices.Equal(got, want) {
		t.Fatalf("VMM worker environment = %v, want %v", got, want)
	}
}

func TestWindowsVirtioMemWorkerDefaultsOnAndCanDisable(t *testing.T) {
	t.Setenv("GANTRY_VIRTIO_MEM", "")
	if got := config.VirtioMemWorkerSetting(); got != "1" {
		t.Fatalf("default virtio-mem worker setting = %q, want 1", got)
	}
	t.Setenv("GANTRY_VIRTIO_MEM", "off")
	if got := config.VirtioMemWorkerSetting(); got != "0" {
		t.Fatalf("disabled virtio-mem worker setting = %q, want 0", got)
	}
}
