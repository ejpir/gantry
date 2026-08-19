package worker

import (
	"os"

	"github.com/ejpir/gantry/internal/sandbox/config"
)

// Env is the explicit child environment allowlist: no secret material. Most
// GANTRY_* knobs travel in bootstrap config; these diagnostic-only switches
// must be present before the worker constructs its subsystem.
func Env() []string {
	// Windows' Winsock provider catalog needs SystemRoot to initialize even
	// when every network capability is an already-connected socket. Preserve
	// only non-secret OS bootstrap paths; the daemon's general environment is
	// still not inherited.
	out := make([]string, 0, 11)
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
