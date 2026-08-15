package virtio

import (
	"encoding/binary"
	"testing"
)

const (
	virtqueueMMIORecordSize    = 14
	virtqueueMMIOMaxOperations = 256
)

const (
	mmioFuzzDeviceFeaturesSel = iota
	mmioFuzzDriverFeatures
	mmioFuzzDriverFeaturesSel
	mmioFuzzQueueSel
	mmioFuzzQueueNum
	mmioFuzzQueueReady
	mmioFuzzQueueNotify
	mmioFuzzInterruptACK
	mmioFuzzStatus
	mmioFuzzDescLow
	mmioFuzzDescHigh
	mmioFuzzAvailLow
	mmioFuzzAvailHigh
	mmioFuzzUsedLow
	mmioFuzzUsedHigh
	mmioFuzzConfigStart
	mmioFuzzConfigEnd
)

var virtqueueMMIOOffsets = [...]uint64{
	0x014, 0x020, 0x024, 0x030, 0x038, 0x044, 0x050, 0x064, 0x070,
	0x080, 0x084, 0x090, 0x094, 0x0a0, 0x0a4, 0x100, 0x1fc,
}

type fuzzTransportState struct {
	featureSel uint32
	driverFeat uint64
	driverSel  uint32
	queueSel   int
	queue      virtq
	status     uint32
	isr        uint32
}

// FuzzVirtqueueMMIO drives the transport as a hostile guest would: arbitrary
// register sequencing interleaved with guest-RAM mutations. Each notification
// consumes at most one chain through fuzzQueueDevice, keeping every invocation
// deterministic and bounded while still reaching descriptor and used-ring I/O.
func FuzzVirtqueueMMIO(f *testing.F) {
	for _, seed := range virtqueueMMIOSeeds() {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) == 0 || len(input) > 1+virtqueueMMIORecordSize*virtqueueMMIOMaxOperations {
			return
		}
		backing := make([]byte, virtqueueFuzzRAMSize)
		var memory *RAM
		if input[0]&1 != 0 {
			memory = NewSplitRAM(backing, virtqueueFuzzLowSize, virtqueueFuzzHighBase)
		} else {
			memory = NewRAM(backing, 0)
		}
		device := new(fuzzQueueDevice)
		core := NewCoreAt(device, memory, 0, 0, func(int, bool) {}, "fuzz-mmio")

		operations := input[1:]
		for len(operations) >= virtqueueMMIORecordSize {
			record := operations[:virtqueueMMIORecordSize]
			operations = operations[virtqueueMMIORecordSize:]
			selector := int(record[1]) % len(virtqueueMMIOOffsets)
			address := binary.LittleEndian.Uint32(record[2:6])
			value := binary.LittleEndian.Uint32(record[6:10])

			switch record[0] & 3 {
			case 0: // write a transport register selected from the useful set
				fuzzWriteMMIO(t, core, device, virtqueueMMIOOffsets[selector], value)
			case 1: // write an arbitrary aligned or unaligned MMIO offset
				fuzzWriteMMIO(t, core, device, uint64(address&0x3ff), value)
			case 2: // reads must never mutate transport state
				before := snapshotFuzzTransport(core)
				lengths := [...]uint32{0, 1, 2, 3, 4, 8, ^uint32(0)}
				_ = core.MMIORead(virtqueueMMIOOffsets[selector], lengths[int(record[10])%len(lengths)])
				if after := snapshotFuzzTransport(core); after != before {
					t.Fatalf("MMIO read mutated transport: before=%+v after=%+v", before, after)
				}
			case 3: // mutate up to eight bytes of mapped or unmapped guest RAM
				before := snapshotFuzzTransport(core)
				guestAddress := uint64(address)
				if record[1]&0x80 != 0 {
					if input[0]&1 != 0 && record[1]&0x40 != 0 {
						guestAddress = virtqueueFuzzHighBase + uint64(address%virtqueueFuzzLowSize)
					} else {
						guestAddress = uint64(address % virtqueueFuzzRAMSize)
					}
				}
				width := 1 << ((record[1] >> 4) & 3)
				_ = memory.writeAt(guestAddress, record[6:6+width])
				if after := snapshotFuzzTransport(core); after != before {
					t.Fatalf("guest RAM write mutated transport: before=%+v after=%+v", before, after)
				}
			}
			assertFuzzTransport(t, core)
		}
	})
}

func fuzzWriteMMIO(t *testing.T, core *Core, device *fuzzQueueDevice, offset uint64, value uint32) {
	t.Helper()
	before := snapshotFuzzTransport(core)
	beforeNotifications := device.notifications
	beforeResets := device.resets
	shouldNotify := offset == 0x050 && int(value) < len(core.queues) && core.queues[value].ready
	core.MMIOWrite(offset, value)

	switch offset {
	case 0x014:
		if core.featureSel != value {
			t.Fatalf("feature selector = %#x, want %#x", core.featureSel, value)
		}
	case 0x020:
		want := before.driverFeat
		if before.driverSel == 1 {
			want = want&0xffffffff | uint64(value)<<32
		} else {
			want = want&0xffffffff00000000 | uint64(value)
		}
		if core.driverFeat != want {
			t.Fatalf("driver features = %#x, want %#x", core.driverFeat, want)
		}
	case 0x024:
		if core.driverSel != value {
			t.Fatalf("driver selector = %#x, want %#x", core.driverSel, value)
		}
	case 0x030:
		want := before.queueSel
		if int(value) < len(core.queues) {
			want = int(value)
		}
		if core.queueSel != want {
			t.Fatalf("queue selector = %d, want %d", core.queueSel, want)
		}
	case 0x038:
		want := before.queue.num
		if fuzzValidQueueSize(value) {
			want = value
		}
		if core.queues[before.queueSel].num != want {
			t.Fatalf("queue size = %d, want %d", core.queues[before.queueSel].num, want)
		}
	case 0x044:
		want := value == 1 && before.queue.numValid()
		if core.queues[before.queueSel].ready != want {
			t.Fatalf("queue ready = %v, want %v", core.queues[before.queueSel].ready, want)
		}
	case 0x050:
		want := beforeNotifications
		if shouldNotify {
			want++
		}
		if device.notifications != want {
			t.Fatalf("notifications = %d, want %d", device.notifications, want)
		}
	case 0x064:
		if core.isr != before.isr&^value {
			t.Fatalf("interrupt status = %#x, want %#x", core.isr, before.isr&^value)
		}
	case 0x070:
		if value == 0 {
			if device.resets != beforeResets+1 {
				t.Fatalf("device resets = %d, want %d", device.resets, beforeResets+1)
			}
			assertFuzzTransportReset(t, core)
		} else if core.status != before.status|value {
			t.Fatalf("device status = %#x, want %#x", core.status, before.status|value)
		}
	case 0x080:
		want := before.queue.descAddr&0xffffffff00000000 | uint64(value)
		if core.queues[before.queueSel].descAddr != want {
			t.Fatalf("descriptor address = %#x, want %#x", core.queues[before.queueSel].descAddr, want)
		}
	case 0x084:
		want := before.queue.descAddr&0xffffffff | uint64(value)<<32
		if core.queues[before.queueSel].descAddr != want {
			t.Fatalf("descriptor address = %#x, want %#x", core.queues[before.queueSel].descAddr, want)
		}
	case 0x090:
		want := before.queue.availAddr&0xffffffff00000000 | uint64(value)
		if core.queues[before.queueSel].availAddr != want {
			t.Fatalf("available address = %#x, want %#x", core.queues[before.queueSel].availAddr, want)
		}
	case 0x094:
		want := before.queue.availAddr&0xffffffff | uint64(value)<<32
		if core.queues[before.queueSel].availAddr != want {
			t.Fatalf("available address = %#x, want %#x", core.queues[before.queueSel].availAddr, want)
		}
	case 0x0a0:
		want := before.queue.usedAddr&0xffffffff00000000 | uint64(value)
		if core.queues[before.queueSel].usedAddr != want {
			t.Fatalf("used address = %#x, want %#x", core.queues[before.queueSel].usedAddr, want)
		}
	case 0x0a4:
		want := before.queue.usedAddr&0xffffffff | uint64(value)<<32
		if core.queues[before.queueSel].usedAddr != want {
			t.Fatalf("used address = %#x, want %#x", core.queues[before.queueSel].usedAddr, want)
		}
	}
}

func snapshotFuzzTransport(core *Core) fuzzTransportState {
	return fuzzTransportState{
		featureSel: core.featureSel,
		driverFeat: core.driverFeat,
		driverSel:  core.driverSel,
		queueSel:   core.queueSel,
		queue:      core.queues[0],
		status:     core.status,
		isr:        core.isr,
	}
}

func assertFuzzTransport(t *testing.T, core *Core) {
	t.Helper()
	if core.queueSel < 0 || core.queueSel >= len(core.queues) {
		t.Fatalf("queue selector outside device queues: %d", core.queueSel)
	}
	for index := range core.queues {
		queue := &core.queues[index]
		if queue.num != 0 && !queue.numValid() {
			t.Fatalf("queue %d retained invalid size %d", index, queue.num)
		}
		if queue.ready && !queue.numValid() {
			t.Fatalf("queue %d ready with invalid size %d", index, queue.num)
		}
	}
}

func assertFuzzTransportReset(t *testing.T, core *Core) {
	t.Helper()
	if core.featureSel != 0 || core.driverFeat != 0 || core.driverSel != 0 ||
		core.status != 0 || core.isr != 0 || core.queueSel != 0 {
		t.Fatalf("transport state survived reset: %+v", snapshotFuzzTransport(core))
	}
	for index, queue := range core.queues {
		if queue != (virtq{}) {
			t.Fatalf("queue %d survived reset: %+v", index, queue)
		}
	}
}

func fuzzValidQueueSize(size uint32) bool {
	return size >= 1 && size <= virtqSize && size&(size-1) == 0
}

func virtqueueMMIOSeeds() [][]byte {
	var descriptorAddress [8]byte
	binary.LittleEndian.PutUint64(descriptorAddress[:], virtqueueFuzzDataAddr)
	var descriptorTail [8]byte
	binary.LittleEndian.PutUint32(descriptorTail[:4], 16)
	var available [8]byte
	binary.LittleEndian.PutUint16(available[2:4], 1)

	validQueue := newVirtqueueMMIOSeed(0,
		mmioFuzzWrite(mmioFuzzQueueSel, 0),
		mmioFuzzWrite(mmioFuzzQueueNum, 8),
		mmioFuzzWrite(mmioFuzzDescLow, virtqueueFuzzDescAddr),
		mmioFuzzWrite(mmioFuzzAvailLow, virtqueueFuzzAvailAddr),
		mmioFuzzWrite(mmioFuzzUsedLow, virtqueueFuzzUsedAddr),
		mmioFuzzRAMWrite(virtqueueFuzzDescAddr, descriptorAddress, 8),
		mmioFuzzRAMWrite(virtqueueFuzzDescAddr+8, descriptorTail, 8),
		mmioFuzzRAMWrite(virtqueueFuzzAvailAddr, available, 8),
		mmioFuzzWrite(mmioFuzzQueueReady, 1),
		mmioFuzzWrite(mmioFuzzQueueNotify, 0),
		mmioFuzzRead(mmioFuzzInterruptACK),
		mmioFuzzWrite(mmioFuzzInterruptACK, virtioIntUsedBuffer),
	)
	invalidQueue := newVirtqueueMMIOSeed(0,
		mmioFuzzWrite(mmioFuzzQueueNum, 3),
		mmioFuzzWrite(mmioFuzzQueueReady, 1),
		mmioFuzzWrite(mmioFuzzQueueNotify, 0),
		mmioFuzzWrite(mmioFuzzQueueSel, ^uint32(0)),
		mmioFuzzArbitraryWrite(0x038, 127),
	)
	featureReset := newVirtqueueMMIOSeed(0,
		mmioFuzzWrite(mmioFuzzDeviceFeaturesSel, 1),
		mmioFuzzWrite(mmioFuzzDriverFeaturesSel, 1),
		mmioFuzzWrite(mmioFuzzDriverFeatures, 0xdeadbeef),
		mmioFuzzWrite(mmioFuzzStatus, 4),
		mmioFuzzWrite(mmioFuzzStatus, 0),
	)
	addressHalves := newVirtqueueMMIOSeed(0,
		mmioFuzzWrite(mmioFuzzDescLow, 0x89abcdef),
		mmioFuzzWrite(mmioFuzzDescHigh, 0x01234567),
		mmioFuzzWrite(mmioFuzzAvailLow, ^uint32(0)),
		mmioFuzzWrite(mmioFuzzAvailHigh, ^uint32(0)),
		mmioFuzzWrite(mmioFuzzUsedLow, virtqueueFuzzUsedAddr),
		mmioFuzzWrite(mmioFuzzUsedHigh, 0),
	)
	splitRAM := newVirtqueueMMIOSeed(1,
		mmioFuzzRAMWrite(virtqueueFuzzLowSize-1, [8]byte{1, 2}, 2),
		mmioFuzzRAMWrite(virtqueueFuzzHighBase, [8]byte{3, 4, 5, 6}, 4),
		mmioFuzzRead(mmioFuzzConfigStart),
		mmioFuzzRead(mmioFuzzConfigEnd),
	)

	return [][]byte{{0}, {1}, validQueue, invalidQueue, featureReset, addressHalves, splitRAM}
}

func newVirtqueueMMIOSeed(mode byte, records ...[]byte) []byte {
	seed := []byte{mode}
	for _, record := range records {
		seed = append(seed, record...)
	}
	return seed
}

func mmioFuzzWrite(selector int, value uint32) []byte {
	record := make([]byte, virtqueueMMIORecordSize)
	record[1] = byte(selector)
	binary.LittleEndian.PutUint32(record[6:10], value)
	return record
}

func mmioFuzzArbitraryWrite(offset, value uint32) []byte {
	record := make([]byte, virtqueueMMIORecordSize)
	record[0] = 1
	binary.LittleEndian.PutUint32(record[2:6], offset)
	binary.LittleEndian.PutUint32(record[6:10], value)
	return record
}

func mmioFuzzRead(selector int) []byte {
	record := make([]byte, virtqueueMMIORecordSize)
	record[0] = 2
	record[1] = byte(selector)
	record[10] = 4
	return record
}

func mmioFuzzRAMWrite(address uint32, payload [8]byte, width int) []byte {
	record := make([]byte, virtqueueMMIORecordSize)
	record[0] = 3
	switch width {
	case 1:
		record[1] = 0 << 4
	case 2:
		record[1] = 1 << 4
	case 4:
		record[1] = 2 << 4
	case 8:
		record[1] = 3 << 4
	default:
		panic("invalid fuzz RAM write width")
	}
	binary.LittleEndian.PutUint32(record[2:6], address)
	copy(record[6:14], payload[:])
	return record
}
