//go:build darwin

package vmmworker

import "os"

// openHypervisorDevice: Hypervisor.framework needs no device node —
// hv_vm_create is an entitlement-gated syscall — so there is nothing
// to pass on darwin.
func openHypervisorDevice() (*os.File, error) { return nil, nil }
