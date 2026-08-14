//go:build windows

package vmm

import (
	"fmt"
	"runtime"
)

func platformMaxVCPUs() int { return MaxVCPUs }

func validatePlatformResources(vcpus int) error {
	if runtime.GOARCH != "amd64" {
		return fmt.Errorf("WHPX virtualization is supported only on windows/amd64")
	}
	return nil
}
