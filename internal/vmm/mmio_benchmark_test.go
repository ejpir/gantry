package vmm

import (
	"testing"

	"github.com/ejpir/gantry/internal/virtio"
)

func BenchmarkHandleVirtioMMIO(b *testing.B) {
	machine := &Machine{
		arch: "amd64",
		mem:  virtio.NewRAM(make([]byte, 4096), 0),
	}
	for range len(x86MMIOIRQs) {
		if _, err := machine.addVirtio(virtio.NewRNG(), "rng"); err != nil {
			b.Fatal(err)
		}
	}
	address := machine.virtios[len(machine.virtios)-1].Base()

	b.ReportAllocs()
	for b.Loop() {
		if value := machine.handleMMIO(false, address, nil, 4); value != 0x74726976 {
			b.Fatalf("MMIO magic = %#x", value)
		}
	}
}
