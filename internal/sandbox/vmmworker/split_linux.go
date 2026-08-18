//go:build linux

package vmmworker

import "os"

// openHypervisorDevice pre-opens /dev/kvm for the worker's descriptor
// table. Under confinement the worker's private /dev is empty, so the
// hypervisor handle must arrive already open.
func openHypervisorDevice() (*os.File, error) {
	return os.OpenFile("/dev/kvm", os.O_RDWR, 0)
}
