//go:build linux || darwin

package vmmworker

import (
	"os"

	"github.com/ejpir/gantry/internal/sandbox/config"
)

// vmmWorkerEnv is the VMM role's explicit child environment allowlist. Most
// GANTRY_* knobs travel in bootstrap config; these diagnostic-only switches
// must be present before the worker constructs the VMM.
func vmmWorkerEnv() []string {
	out := make([]string, 0, 5)
	if os.Getenv("GANTRY_DEBUG_RTC") != "" {
		out = append(out, "GANTRY_DEBUG_RTC=1")
	}
	if os.Getenv("GANTRY_PREFAULT_RAM") != "" {
		out = append(out, "GANTRY_PREFAULT_RAM=1")
	}
	if os.Getenv("GANTRY_BOOT_PROFILE") == "1" {
		out = append(out, "GANTRY_BOOT_PROFILE=1")
	}
	if os.Getenv("GANTRY_VHOST_STATS") == "1" {
		out = append(out, "GANTRY_VHOST_STATS=1")
	}
	if setting := config.VirtioMemWorkerSetting(); setting != "" {
		out = append(out, "GANTRY_VIRTIO_MEM="+setting)
	}
	return out
}
