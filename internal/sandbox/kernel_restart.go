package sandbox

import (
	"fmt"
	"path/filepath"

	"github.com/ejpir/gantry/internal/guestasset"
)

const (
	kernelPolicyRelease = "release"
	kernelPolicyPinned  = "pinned"
)

// refreshKernelForRestart resolves the kernel that the current Gantry release
// should boot. Explicit kernels remain pinned. Legacy configs are considered
// release-managed only when their path unambiguously matches Gantry's
// versioned release-cache layout.
func refreshKernelForRestart(cfg RunConfig, progress func(string, ...any)) (RunConfig, bool, error) {
	original := cfg
	switch cfg.KernelPolicy {
	case kernelPolicyRelease:
		// Already known to follow Gantry releases.
	case kernelPolicyPinned:
		return cfg, false, nil
	case "":
		if guestasset.IsManagedReleaseKernel(cfg.Kernel) {
			cfg.KernelPolicy = kernelPolicyRelease
		} else {
			cfg.KernelPolicy = kernelPolicyPinned
			return cfg, kernelSelectionChanged(original, cfg), nil
		}
	default:
		return cfg, false, fmt.Errorf("unsupported saved kernel policy %q", cfg.KernelPolicy)
	}

	kernel := guestasset.DefaultKernel()
	if cfg.Runtime == "runsc" {
		kernel = guestasset.GVisorKernel(kernel)
	}
	ensured, err := guestasset.EnsureKernel(kernel, progress)
	if err != nil {
		return original, false, fmt.Errorf("prepare release kernel: %w", err)
	}
	absolute, err := filepath.Abs(ensured)
	if err != nil {
		return original, false, fmt.Errorf("resolve release kernel path %q: %w", ensured, err)
	}
	cfg.Kernel = absolute
	return cfg, kernelSelectionChanged(original, cfg), nil
}

func kernelSelectionChanged(before, after RunConfig) bool {
	return before.Kernel != after.Kernel || before.KernelPolicy != after.KernelPolicy
}

// refreshSavedKernelForRestart atomically publishes a migrated/refreshed
// config before the daemon is spawned, ensuring it reads the same new kernel
// selected by the launcher.
func refreshSavedKernelForRestart(dir string, cfg RunConfig, progress func(string, ...any)) (RunConfig, bool, error) {
	refreshed, changed, err := refreshKernelForRestart(cfg, progress)
	if err != nil || !changed {
		return refreshed, changed, err
	}
	store := &ConfigStore{path: filepath.Join(dir, "sandbox.json"), cfg: refreshed}
	if err := store.writeLocked(); err != nil {
		return cfg, false, fmt.Errorf("persist refreshed kernel: %w", err)
	}
	return refreshed, true, nil
}
