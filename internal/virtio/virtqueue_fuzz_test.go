package virtio

import (
	"encoding/binary"
	"testing"
)

const (
	virtqueueFuzzHeaderSize = 16
	virtqueueFuzzRAMSize    = 16 << 10
	virtqueueFuzzLowSize    = 8 << 10
	virtqueueFuzzHighBase   = 0x10000
	virtqueueFuzzDescAddr   = 0x100
	virtqueueFuzzAvailAddr  = 0x900
	virtqueueFuzzUsedAddr   = 0xb00
	virtqueueFuzzDataAddr   = 0x2000
	virtqueueFuzzChainLimit = 4 << 10
)

// fuzzQueueDevice keeps the hot fuzz target independent of files, sockets,
// goroutines, and platform build tags. Device protocol fuzzers sit above this
// common guest-controlled descriptor boundary.
type fuzzQueueDevice struct {
	core          *Core
	notifications uint32
	resets        uint32
}

func (*fuzzQueueDevice) deviceID() uint32           { return 0xffff }
func (*fuzzQueueDevice) features() uint64           { return 0 }
func (*fuzzQueueDevice) numQueues() int             { return 1 }
func (*fuzzQueueDevice) configRead(uint64, []byte)  {}
func (*fuzzQueueDevice) configWrite(uint64, []byte) {}
func (d *fuzzQueueDevice) reset()                   { d.resets++ }
func (d *fuzzQueueDevice) handleQueue(qn int) {
	d.notifications++
	head, _, ok := d.core.availChain(qn)
	if ok {
		d.core.pushUsed(&d.core.queues[qn], head, 0)
	}
}
func (d *fuzzQueueDevice) setCore(core *Core)     { d.core = core }
func (*fuzzQueueDevice) maxChainBytes(int) uint64 { return virtqueueFuzzChainLimit }

type fuzzQueueDesc struct {
	addr  uint64
	len   uint32
	flags uint16
	next  uint16
}

// FuzzVirtqueueChain exercises the split-ring parser with raw guest RAM and
// queue configuration. Malformed input is expected to be rejected; accepted
// chains must satisfy the invariants every device handler relies on.
func FuzzVirtqueueChain(f *testing.F) {
	for _, seed := range virtqueueFuzzSeeds() {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) < virtqueueFuzzHeaderSize || len(input) > virtqueueFuzzHeaderSize+virtqueueFuzzRAMSize {
			return
		}

		backing := make([]byte, virtqueueFuzzRAMSize)
		copy(backing, input[virtqueueFuzzHeaderSize:])
		var memory *RAM
		if input[1]&1 != 0 {
			memory = NewSplitRAM(backing, virtqueueFuzzLowSize, virtqueueFuzzHighBase)
		} else {
			memory = NewRAM(backing, 0)
		}

		device := new(fuzzQueueDevice)
		core := NewCoreAt(device, memory, 0, 0, func(int, bool) {}, "fuzz-queue")
		queue := &core.queues[0]
		queue.ready = true
		queue.num = uint32(input[0])
		queue.lastAvail = binary.LittleEndian.Uint16(input[2:4])
		queue.descAddr = uint64(binary.LittleEndian.Uint32(input[4:8]))
		queue.availAddr = uint64(binary.LittleEndian.Uint32(input[8:12]))
		queue.usedAddr = uint64(binary.LittleEndian.Uint32(input[12:16]))

		before := queue.lastAvail
		head, chain, ok := core.availChain(0)
		advanced := uint16(queue.lastAvail - before)
		if advanced > 1 {
			t.Fatalf("avail parser advanced %d entries in one call", advanced)
		}
		if !ok {
			return
		}
		if advanced != 1 {
			t.Fatalf("accepted chain without consuming one avail entry")
		}
		if uint32(head) >= queue.num {
			t.Fatalf("accepted head %d outside queue size %d", head, queue.num)
		}
		maxDescriptors := min(int(queue.num), virtqMaxChainDescriptors)
		if len(chain) == 0 || len(chain) > maxDescriptors {
			t.Fatalf("accepted chain length %d outside [1,%d]", len(chain), maxDescriptors)
		}

		var total uint64
		for index, descriptor := range chain {
			if descriptor.flags&vringDescFIndirect != 0 {
				t.Fatalf("accepted unnegotiated indirect descriptor %d", index)
			}
			if !memory.contains(descriptor.addr, uint64(descriptor.len)) {
				t.Fatalf("accepted descriptor %d outside guest RAM: %#x+%#x", index, descriptor.addr, descriptor.len)
			}
			total += uint64(descriptor.len)
		}
		if total > core.chainLimit(0) {
			t.Fatalf("accepted %d-byte chain over %d-byte limit", total, core.chainLimit(0))
		}

		readable, writable := splitChain(chain)
		if _, err := core.readChains(readable); err != nil {
			t.Fatalf("accepted readable chain failed: %v", err)
		}
		if _, err := core.writeChains(writable, []byte("virtqueue-fuzz-write-probe")); err != nil {
			t.Fatalf("accepted writable chain failed: %v", err)
		}
	})
}

func virtqueueFuzzSeeds() [][]byte {
	valid := []fuzzQueueDesc{{addr: virtqueueFuzzDataAddr, len: 16}}
	selfCycle := []fuzzQueueDesc{{addr: virtqueueFuzzDataAddr, len: 1, flags: vringDescFNext, next: 0}}
	twoNodeCycle := []fuzzQueueDesc{
		{addr: virtqueueFuzzDataAddr, len: 1, flags: vringDescFNext, next: 1},
		{addr: virtqueueFuzzDataAddr + 1, len: 1, flags: vringDescFNext, next: 0},
	}
	chain65 := virtqueueFuzzChain(65)
	chain66 := virtqueueFuzzChain(66)

	return [][]byte{
		newVirtqueueFuzzSeed(0, 8, 0, 1, 0, valid),
		newVirtqueueFuzzSeed(0, 0, 0, 1, 0, valid),
		newVirtqueueFuzzSeed(0, 3, 0, 1, 0, valid),
		newVirtqueueFuzzSeed(0, 8, 0, 1, 8, valid),
		newVirtqueueFuzzSeed(0, 8, 0, 1, 0, selfCycle),
		newVirtqueueFuzzSeed(0, 8, 0, 1, 0, twoNodeCycle),
		newVirtqueueFuzzSeed(0, 8, 0, 1, 0, []fuzzQueueDesc{{addr: virtqueueFuzzDataAddr, len: ^uint32(0)}}),
		newVirtqueueFuzzSeed(0, 8, 0, 1, 0, []fuzzQueueDesc{{addr: ^uint64(0) - 7, len: 16}}),
		newVirtqueueFuzzSeed(0, 8, 0, 9, 0, valid),
		newVirtqueueFuzzSeed(0, 8, ^uint16(0), 0, 0, valid),
		newVirtqueueFuzzSeed(0, 8, 0, 1, 0, []fuzzQueueDesc{{addr: virtqueueFuzzDataAddr, len: 16, flags: vringDescFIndirect}}),
		newVirtqueueFuzzSeed(1, 8, 0, 1, 0, []fuzzQueueDesc{{addr: virtqueueFuzzLowSize - 1, len: 2}}),
		newVirtqueueFuzzSeed(1, 8, 0, 1, 0, []fuzzQueueDesc{{addr: virtqueueFuzzHighBase, len: 16}}),
		newVirtqueueFuzzSeed(0, 8, 0, 1, 0, []fuzzQueueDesc{{addr: virtqueueFuzzRAMSize, len: 0}}),
		newVirtqueueFuzzSeed(0, 128, 0, 1, 0, chain65),
		newVirtqueueFuzzSeed(0, 128, 0, 1, 0, chain66),
		newVirtqueueFuzzSeed(0, 8, 0, 1, 0, []fuzzQueueDesc{
			{addr: virtqueueFuzzDataAddr, len: virtqueueFuzzChainLimit / 2, flags: vringDescFNext, next: 1},
			{addr: virtqueueFuzzDataAddr + virtqueueFuzzChainLimit/2, len: virtqueueFuzzChainLimit / 2},
		}),
		newVirtqueueFuzzSeed(0, 8, 0, 1, 0, []fuzzQueueDesc{
			{addr: virtqueueFuzzDataAddr, len: virtqueueFuzzChainLimit / 2, flags: vringDescFNext, next: 1},
			{addr: virtqueueFuzzDataAddr + virtqueueFuzzChainLimit/2, len: virtqueueFuzzChainLimit/2 + 1},
		}),
	}
}

func virtqueueFuzzChain(count int) []fuzzQueueDesc {
	chain := make([]fuzzQueueDesc, count)
	for index := range chain {
		chain[index] = fuzzQueueDesc{addr: virtqueueFuzzDataAddr + uint64(index), len: 1}
		if index+1 < count {
			chain[index].flags = vringDescFNext
			chain[index].next = uint16(index + 1)
		}
	}
	return chain
}

func newVirtqueueFuzzSeed(mode, queueSize byte, lastAvail, availIndex, head uint16, descriptors []fuzzQueueDesc) []byte {
	seed := make([]byte, virtqueueFuzzHeaderSize+virtqueueFuzzRAMSize)
	seed[0] = queueSize
	seed[1] = mode
	binary.LittleEndian.PutUint16(seed[2:4], lastAvail)
	binary.LittleEndian.PutUint32(seed[4:8], virtqueueFuzzDescAddr)
	binary.LittleEndian.PutUint32(seed[8:12], virtqueueFuzzAvailAddr)
	binary.LittleEndian.PutUint32(seed[12:16], virtqueueFuzzUsedAddr)
	ram := seed[virtqueueFuzzHeaderSize:]

	for index, descriptor := range descriptors {
		if index >= virtqSize {
			break
		}
		offset := virtqueueFuzzDescAddr + index*16
		binary.LittleEndian.PutUint64(ram[offset:offset+8], descriptor.addr)
		binary.LittleEndian.PutUint32(ram[offset+8:offset+12], descriptor.len)
		binary.LittleEndian.PutUint16(ram[offset+12:offset+14], descriptor.flags)
		binary.LittleEndian.PutUint16(ram[offset+14:offset+16], descriptor.next)
	}
	binary.LittleEndian.PutUint16(ram[virtqueueFuzzAvailAddr+2:virtqueueFuzzAvailAddr+4], availIndex)
	if queueSize != 0 {
		slot := int(lastAvail % uint16(queueSize))
		offset := virtqueueFuzzAvailAddr + 4 + slot*2
		binary.LittleEndian.PutUint16(ram[offset:offset+2], head)
	}
	return seed
}
