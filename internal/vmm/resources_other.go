//go:build !windows

package vmm

func validatePlatformResources(int) error { return nil }
