//go:build !windows

package vmm

func platformMaxVCPUs() int { return MaxVCPUs }

func validatePlatformResources(int) error { return nil }
