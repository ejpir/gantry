//go:build darwin

package boot

import "testing"

func TestDarwinGuestVCPUMPIDRRoundTrip(t *testing.T) {
	if got, want := VCPUMPIDR(1), uint32(0x100); got != want {
		t.Fatalf("VCPUMPIDR(1) = %#x, want Aff1 value %#x", got, want)
	}
	for id := range 8 {
		mpidr := uint64(0x80000000) | uint64(VCPUMPIDR(id))
		if got := VCPUIndex(mpidr); got != id {
			t.Errorf("VCPUIndex(%#x) = %d, want %d", mpidr, got, id)
		}
	}
}
