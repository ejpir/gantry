//go:build windows

package vmm

import (
	"fmt"
	"runtime"
)

func validatePlatformResources(vcpus int) error {
	if runtime.GOARCH != "amd64" {
		return fmt.Errorf("WHPX virtualization is supported only on windows/amd64")
	}
	if vcpus != 1 {
		return fmt.Errorf("WHPX currently supports exactly one vCPU")
	}
	return nil
}
