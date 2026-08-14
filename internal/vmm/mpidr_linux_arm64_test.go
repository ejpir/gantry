//go:build linux && arm64

package vmm

import "testing"

func TestKVMGuestVCPUMPIDRUsesAff0(t *testing.T) {
	if got, want := guestVCPUMPIDR(1), uint32(1); got != want {
		t.Fatalf("guestVCPUMPIDR(1) = %#x, want Aff0 value %#x", got, want)
	}
}
