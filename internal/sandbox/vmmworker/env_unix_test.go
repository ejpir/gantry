//go:build linux || darwin

package vmmworker

import (
	"slices"
	"testing"
)

func TestVMMWorkerEnvironmentDoesNotInheritHostAuthority(t *testing.T) {
	for _, key := range []string{
		"GANTRY_DEBUG_RTC", "GANTRY_PREFAULT_RAM", "GANTRY_BOOT_PROFILE",
		"GANTRY_VHOST_STATS", "GANTRY_VIRTIO_MEM",
	} {
		t.Setenv(key, "")
	}
	t.Setenv("PATH", "/host/tools")
	t.Setenv("HOME", "/host/home")
	t.Setenv("TMPDIR", "/host/tmp")
	t.Setenv("GANTRY_SECRET_TEST", "must-not-cross")
	t.Setenv("GANTRY_DEBUG_RTC", "1")
	t.Setenv("GANTRY_PREFAULT_RAM", "1")
	t.Setenv("GANTRY_BOOT_PROFILE", "1")
	t.Setenv("GANTRY_VHOST_STATS", "1")
	t.Setenv("GANTRY_VIRTIO_MEM", "true")

	want := []string{
		"GANTRY_DEBUG_RTC=1", "GANTRY_PREFAULT_RAM=1", "GANTRY_BOOT_PROFILE=1",
		"GANTRY_VHOST_STATS=1", "GANTRY_VIRTIO_MEM=1",
	}
	if got := vmmWorkerEnv(); !slices.Equal(got, want) {
		t.Fatalf("VMM worker environment = %v, want %v", got, want)
	}
}
