//go:build darwin

package vmm

import "testing"

func TestDarwinGuestVCPUMPIDRRoundTrip(t *testing.T) {
	if got, want := guestVCPUMPIDR(1), uint32(0x100); got != want {
		t.Fatalf("guestVCPUMPIDR(1) = %#x, want Aff1 value %#x", got, want)
	}
	for id := range 8 {
		mpidr := uint64(0x80000000) | uint64(guestVCPUMPIDR(id))
		if got := guestVCPUIndex(mpidr); got != id {
			t.Errorf("guestVCPUIndex(%#x) = %d, want %d", mpidr, got, id)
		}
	}
}
