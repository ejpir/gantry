package vmmworker

import (
	"os"

	"github.com/ejpir/gantry/internal/sandbox/config"
)

// vmmWorkerEnv is the WHPX role's explicit environment allowlist. Windows'
// runtime and Winsock initialization need a small set of OS bootstrap paths;
// no general supervisor environment is inherited.
func vmmWorkerEnv() []string {
	out := make([]string, 0, 12)
	for _, key := range []string{"SystemRoot", "WINDIR", "SystemDrive", "TEMP", "TMP"} {
		if value := os.Getenv(key); value != "" {
			out = append(out, key+"="+value)
		}
	}
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
	if os.Getenv("GANTRY_WHPX_PIC") != "" {
		out = append(out, "GANTRY_WHPX_PIC=1")
	}
	if os.Getenv("GANTRY_WHPX_PIC_NOPIT") != "" {
		out = append(out, "GANTRY_WHPX_PIC_NOPIT=1")
	}
	return out
}
