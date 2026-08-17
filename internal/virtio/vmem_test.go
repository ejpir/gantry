package virtio

import (
	"encoding/binary"
	"testing"
)

func memRequest(typeID uint16, addr uint64, blocks uint16) []byte {
	request := make([]byte, memRequestSize)
	binary.LittleEndian.PutUint16(request[0:], typeID)
	binary.LittleEndian.PutUint64(request[8:], addr)
	binary.LittleEndian.PutUint16(request[16:], blocks)
	return request
}

func TestVirtioMemPlugStateAndUnplug(t *testing.T) {
	const (
		base  = uint64(4 << 30)
		block = uint64(128 << 20)
	)
	device, err := NewMem(base, 4*block, block)
	if err != nil {
		t.Fatal(err)
	}
	response := device.handleRequest(memRequest(memReqPlug, base, 2))
	if got := binary.LittleEndian.Uint16(response[:]); got != memRespACK {
		t.Fatalf("plug response = %d, want ACK", got)
	}
	if device.pluggedSize != 2*block {
		t.Fatalf("plugged size = %#x, want %#x", device.pluggedSize, 2*block)
	}
	response = device.handleRequest(memRequest(memReqState, base+block, 2))
	if got := binary.LittleEndian.Uint16(response[8:]); got != memStateMixed {
		t.Fatalf("state response = %d, want mixed", got)
	}
	response = device.handleRequest(memRequest(memReqUnplug, base, 1))
	if got := binary.LittleEndian.Uint16(response[:]); got != memRespACK || device.pluggedSize != block {
		t.Fatalf("unplug response = %d, plugged size %#x", got, device.pluggedSize)
	}
	device.handleRequest(memRequest(memReqUnplugAll, 0, 0))
	if device.pluggedSize != 0 {
		t.Fatalf("unplug-all left %#x plugged", device.pluggedSize)
	}
}

func TestVirtioMemRejectsInvalidRanges(t *testing.T) {
	const (
		base  = uint64(4 << 30)
		block = uint64(128 << 20)
	)
	device, err := NewMem(base, 2*block, block)
	if err != nil {
		t.Fatal(err)
	}
	for _, request := range [][]byte{
		memRequest(memReqPlug, base-1, 1),
		memRequest(memReqPlug, base, 0),
		memRequest(memReqPlug, base+2*block, 1),
		memRequest(99, base, 1),
		make([]byte, memRequestSize-1),
	} {
		response := device.handleRequest(request)
		if got := binary.LittleEndian.Uint16(response[:]); got != memRespError {
			t.Fatalf("invalid request response = %d, want error", got)
		}
	}
}

func TestVirtioMemConfig(t *testing.T) {
	const (
		base   = uint64(4 << 30)
		region = uint64(2 << 30)
		block  = uint64(128 << 20)
	)
	device, err := NewMem(base, region, block)
	if err != nil {
		t.Fatal(err)
	}
	var config [memConfigSize]byte
	device.configRead(0, config[:])
	if got := binary.LittleEndian.Uint64(config[0:]); got != block {
		t.Fatalf("block size = %#x, want %#x", got, block)
	}
	if got := binary.LittleEndian.Uint64(config[16:]); got != base {
		t.Fatalf("base = %#x, want %#x", got, base)
	}
	for _, offset := range []int{24, 32, 48} {
		if got := binary.LittleEndian.Uint64(config[offset:]); got != region {
			t.Fatalf("config[%d] = %#x, want %#x", offset, got, region)
		}
	}
}

func TestVirtioMemDeferredRequestRaisesConfigInterrupt(t *testing.T) {
	device, err := NewMem(4<<30, 128<<20, 128<<20)
	if err != nil {
		t.Fatal(err)
	}
	device.DeferRequested()
	var raised bool
	core := NewCoreAt(device, NewRAM(make([]byte, 1<<20), 0), 0xc0000000, 3,
		func(_ int, level bool) { raised = level }, "mem")
	device.RequestAll()
	if device.requestedSize != device.regionSize {
		t.Fatalf("requested size = %#x, want %#x", device.requestedSize, device.regionSize)
	}
	if core.isr&virtioIntConfig == 0 || !raised || core.gen != 1 {
		t.Fatalf("config interrupt: isr=%#x raised=%v generation=%d", core.isr, raised, core.gen)
	}
}
