//go:build linux && arm64

package boot

import "testing"

func TestKVMGuestVCPUMPIDRUsesAff0(t *testing.T) {
	if got, want := VCPUMPIDR(1), uint32(1); got != want {
		t.Fatalf("VCPUMPIDR(1) = %#x, want Aff0 value %#x", got, want)
	}
}
