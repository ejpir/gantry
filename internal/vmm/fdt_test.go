package vmm

import (
	"strings"
	"testing"
)

func TestFDTMultiCPU(t *testing.T) {
	fdt := buildGuestFDT(512<<20, 0, 0, "console=ttyAMA0", 2, 2)
	s := string(fdt)
	// Node names carry KVM's MPIDR Aff0 value: cpu@0, cpu@1.
	for _, want := range []string{"cpu@0", "cpu@1"} {
		if !strings.Contains(s, want) {
			t.Errorf("2-vCPU FDT missing %q", want)
		}
	}
	if strings.Contains(s, "cpu@2") {
		t.Error("2-vCPU FDT has a cpu@2 node")
	}
	fdt1 := buildGuestFDT(512<<20, 0, 0, "", 1)
	if strings.Contains(string(fdt1), "cpu@1") {
		t.Error("default FDT has more than one cpu node")
	}
}
