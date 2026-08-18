package boot

import (
	"fmt"
	"strings"
	"testing"

	"github.com/ejpir/gantry/internal/vmm/devices"
)

func TestFDTMultiCPU(t *testing.T) {
	fdt := BuildGuestFDT(512<<20, 0, 0, "console=ttyAMA0", 2, 2)
	s := string(fdt)
	// Node names carry the MPIDR affinity used by the selected host backend.
	for i := range 2 {
		want := fmt.Sprintf("cpu@%x\x00", VCPUMPIDR(i))
		if !strings.Contains(s, want) {
			t.Errorf("2-vCPU FDT missing %q", want)
		}
	}
	unexpected := fmt.Sprintf("cpu@%x\x00", VCPUMPIDR(2))
	if strings.Contains(s, unexpected) {
		t.Errorf("2-vCPU FDT has a %q node", unexpected)
	}
	fdt1 := BuildGuestFDT(512<<20, 0, 0, "", 1)
	second := fmt.Sprintf("cpu@%x\x00", VCPUMPIDR(1))
	if strings.Contains(string(fdt1), second) {
		t.Error("default FDT has more than one cpu node")
	}
}

// TestFDTConsoleNode pins the PL011 node's name and compatible strings. The
// Linux amba-pl011 driver matches on them exactly; a wrong string means no
// ttyAMA0, no /dev/console, and an arm64 guest that boots to nothing — a
// failure the compiler cannot catch, because these are string literals.
func TestFDTConsoleNode(t *testing.T) {
	s := string(BuildGuestFDT(512<<20, 0, 0, "console=ttyAMA0", 1))
	for _, want := range []string{
		fmt.Sprintf("pl011@%x\x00", devices.PL011Base),
		"arm,pl011\x00arm,primecell\x00",
		"uartclk\x00apb_pclk\x00",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("FDT console node missing %q", want)
		}
	}
}
