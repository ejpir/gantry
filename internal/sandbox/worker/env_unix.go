//go:build linux || darwin

package worker

import (
	"os"

	"github.com/ejpir/gantry/internal/sandbox/config"
)

// Env is the explicit child environment allowlist: no secret material.
// Most GANTRY_* knobs travel in bootstrap config; these diagnostic-only
// switches must be present before the worker constructs the VMM.
func Env() []string {
	out := make([]string, 0, 4)
	// GANTRY_DEBUG_RTC is a debug pass-through (worker-side postmortem
	// logging); it carries no secret material.
	if os.Getenv("GANTRY_DEBUG_RTC") != "" {
		out = append(out, "GANTRY_DEBUG_RTC=1")
	}
	// GANTRY_PREFAULT_RAM likewise: the guest RAM commit happens inside the
	// VMM worker, so the boot-latency experiment is unreachable without it.
	if os.Getenv("GANTRY_PREFAULT_RAM") != "" {
		out = append(out, "GANTRY_PREFAULT_RAM=1")
	}
	// GANTRY_BOOT_PROFILE enables intentionally perturbing vCPU sampling and
	// exit tracing. The low-overhead timeline itself travels in bootstrap.
	if os.Getenv("GANTRY_BOOT_PROFILE") == "1" {
		out = append(out, "GANTRY_BOOT_PROFILE=1")
	}
	// GANTRY_VHOST_STATS enables aggregate, worker-local FUSE request
	// timings. It carries no authority and is consumed only by the VMM
	// worker after the vhost backend has been constructed.
	if os.Getenv("GANTRY_VHOST_STATS") == "1" {
		out = append(out, "GANTRY_VHOST_STATS=1")
	}
	if setting := config.VirtioMemWorkerSetting(); setting != "" {
		out = append(out, "GANTRY_VIRTIO_MEM="+setting)
	}
	return out
}
