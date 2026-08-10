//go:build linux || darwin

package virtio

import (
	"testing"

	"github.com/hanwen/go-fuse/v2/fuse"
)

type benchmarkDevice struct{ core *Core }

func (*benchmarkDevice) deviceID() uint32           { return 0 }
func (*benchmarkDevice) features() uint64           { return 0 }
func (*benchmarkDevice) numQueues() int             { return 1 }
func (*benchmarkDevice) configRead(uint64, []byte)  {}
func (*benchmarkDevice) configWrite(uint64, []byte) {}
func (*benchmarkDevice) reset()                     {}
func (*benchmarkDevice) handleQueue(int)            {}
func (d *benchmarkDevice) setCore(core *Core)       { d.core = core }
func (*benchmarkDevice) maxChainBytes(int) uint64   { return 64 << 10 }

func BenchmarkVirtqueuePop(b *testing.B) {
	ram := NewRAM(make([]byte, 2<<20), ramBase)
	device := new(benchmarkDevice)
	core := NewCoreAt(device, ram, MMIOBaseArm64, MMIOIRQArm64, func(int, bool) {}, "benchmark")
	setupQueue(ram, core, 0, 8)
	putDesc(ram, 0, 0, ramBase+testDataAddr, 750, vringDescFNext, 1)
	putDesc(ram, 0, 1, ramBase+testDataAddr+1024, 750, 0, 0)
	availPush(ram, 0, 0)

	b.ReportAllocs()
	for b.Loop() {
		core.queues[0].lastAvail = 0
		_, chain, ok := core.availChain(0)
		if !ok || len(chain) != 2 {
			b.Fatalf("availChain = (_, %d, %v), want two descriptors", len(chain), ok)
		}
	}
}

func BenchmarkReadChains(b *testing.B) {
	ram := NewRAM(make([]byte, 2<<20), ramBase)
	device := new(benchmarkDevice)
	core := NewCoreAt(device, ram, MMIOBaseArm64, MMIOIRQArm64, func(int, bool) {}, "benchmark")
	descriptors := []desc{
		{addr: ramBase + testDataAddr, len: 750},
		{addr: ramBase + testDataAddr + 1024, len: 750},
	}
	if _, err := core.readChains(descriptors); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.SetBytes(1500)
	b.ResetTimer()
	for b.Loop() {
		data, err := core.readChains(descriptors)
		if err != nil || len(data) != 1500 {
			b.Fatalf("readChains = %d bytes, %v", len(data), err)
		}
	}
}

type benchmarkFSHandler struct{}

func (benchmarkFSHandler) HandleRequest(_ [][]byte, out [][]byte) (int, fuse.Status) {
	if len(out) == 0 || len(out[0]) < 16 {
		return 0, fuse.EIO
	}
	out[0][0] = 1
	return 16, fuse.OK
}

func BenchmarkVirtioFSRequest(b *testing.B) {
	ram := NewRAM(make([]byte, 2<<20), ramBase)
	device, err := NewFS("benchmark", benchmarkFSHandler{}, nil)
	if err != nil {
		b.Fatal(err)
	}
	core := NewCoreAt(device, ram, MMIOBaseArm64, MMIOIRQArm64, func(int, bool) {}, "fs")
	setupQueue(ram, core, virtioFSRequestQ, 8)
	putDesc(ram, virtioFSRequestQ, 0, ramBase+testDataAddr, 40, vringDescFNext, 1)
	putDesc(ram, virtioFSRequestQ, 1, ramBase+testDataAddr+64, 8, vringDescFNext, 2)
	putDesc(ram, virtioFSRequestQ, 2, ramBase+testDataAddr+128, 16, vringDescFNext|vringDescFWrite, 3)
	putDesc(ram, virtioFSRequestQ, 3, ramBase+testDataAddr+192, 8, vringDescFWrite, 0)

	b.ReportAllocs()
	for b.Loop() {
		availPush(ram, virtioFSRequestQ, 0)
		core.MMIOWrite(0x050, virtioFSRequestQ)
	}
}
