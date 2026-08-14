package vmm

import (
	"fmt"
	"strings"
	"testing"
)

func TestFDTMultiCPU(t *testing.T) {
	fdt := buildGuestFDT(512<<20, 0, 0, "console=ttyAMA0", 2, 2)
	s := string(fdt)
	// Node names carry the MPIDR affinity used by the selected host backend.
	for i := range 2 {
		want := fmt.Sprintf("cpu@%x\x00", guestVCPUMPIDR(i))
		if !strings.Contains(s, want) {
			t.Errorf("2-vCPU FDT missing %q", want)
		}
	}
	unexpected := fmt.Sprintf("cpu@%x\x00", guestVCPUMPIDR(2))
	if strings.Contains(s, unexpected) {
		t.Errorf("2-vCPU FDT has a %q node", unexpected)
	}
	fdt1 := buildGuestFDT(512<<20, 0, 0, "", 1)
	second := fmt.Sprintf("cpu@%x\x00", guestVCPUMPIDR(1))
	if strings.Contains(string(fdt1), second) {
		t.Error("default FDT has more than one cpu node")
	}
}
