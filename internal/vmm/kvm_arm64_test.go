//go:build linux && arm64

package vmm

import "testing"

func TestKVMArmVCPUFeatures(t *testing.T) {
	if got, want := kvmArmVCPUFeatures(0), uint32(1<<kvmArmVcpuPSCI02); got != want {
		t.Fatalf("boot CPU features = %#x, want %#x", got, want)
	}
	if got, want := kvmArmVCPUFeatures(1), uint32(1<<kvmArmVcpuPSCI02|1<<kvmArmVcpuPowerOff); got != want {
		t.Fatalf("secondary CPU features = %#x, want %#x", got, want)
	}
}

func TestKVMArmVGICRedistributorRegion(t *testing.T) {
	for _, vcpus := range []int{1, 2, 8} {
		got := kvmArmRedistRegion(vcpus)
		want := uint64(vcpus)<<52 | uint64(0x080a0000)
		if got != want {
			t.Fatalf("%d-vCPU redistributor region = %#x, want %#x", vcpus, got, want)
		}
	}
}

func TestKVMArmSPIIRQEncoding(t *testing.T) {
	for _, intid := range []int{32, 33, 48, 127} {
		want := uint32(1<<24 | intid)
		if got := kvmArmSPIIRQ(intid); got != want {
			t.Fatalf("kvmArmSPIIRQ(%d) = %#x, want %#x", intid, got, want)
		}
	}
}
