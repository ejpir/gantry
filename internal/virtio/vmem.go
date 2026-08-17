package virtio

import (
	"encoding/binary"
	"fmt"
)

// virtio-mem (device ID 24) presents a hotpluggable physical-address region.
// Gantry omits the region from the x86 e820 map and makes the platform mapping
// accessible before increasing requestedSize; Linux then discovers and
// onlines it through this device. Windows defers both host commitment and the
// WHPX GPA mapping until the post-readiness request.
const (
	MemDeviceID = 24

	memReqPlug      = 0
	memReqUnplug    = 1
	memReqUnplugAll = 2
	memReqState     = 3

	memRespACK   = 0
	memRespNACK  = 1
	memRespBusy  = 2
	memRespError = 3

	memStatePlugged   = 0
	memStateUnplugged = 1
	memStateMixed     = 2

	memRequestSize  = 24
	memResponseSize = 10
	memConfigSize   = 56
)

type Mem struct {
	core          *Core
	addr          uint64
	regionSize    uint64
	blockSize     uint64
	requestedSize uint64
	pluggedSize   uint64
	plugged       []bool
}

func NewMem(addr, regionSize, blockSize uint64) (*Mem, error) {
	if regionSize == 0 || blockSize == 0 || blockSize&(blockSize-1) != 0 {
		return nil, fmt.Errorf("virtio-mem: region and power-of-two block size must be nonzero")
	}
	if addr%blockSize != 0 || regionSize%blockSize != 0 || addr > ^uint64(0)-regionSize {
		return nil, fmt.Errorf("virtio-mem: region %#x+%#x is not block-aligned", addr, regionSize)
	}
	blocks := regionSize / blockSize
	if blocks > uint64(^uint(0)>>1) {
		return nil, fmt.Errorf("virtio-mem: block count %d exceeds host address space", blocks)
	}
	return &Mem{
		addr: addr, regionSize: regionSize, blockSize: blockSize,
		requestedSize: regionSize, plugged: make([]bool, int(blocks)),
	}, nil
}

// DeferRequested makes the device probe with no requested memory. Gantry uses
// this before the device is attached when a vsock readiness handshake is
// available, then calls RequestAll after the daemon publishes readiness.
// Keeping these as two explicit phases prevents memory hotplug work from
// delaying PID 1 or the start command's usable-VM boundary.
func (v *Mem) DeferRequested() { v.requestedSize = 0 }

// RequestAll publishes the device's full capacity and raises the config-change
// interrupt required to make an already-probed Linux driver re-read it.
func (v *Mem) RequestAll() {
	if v.core == nil {
		v.requestedSize = v.regionSize
		return
	}
	v.core.mu.Lock()
	defer v.core.mu.Unlock()
	if v.requestedSize == v.regionSize {
		return
	}
	v.requestedSize = v.regionSize
	v.core.gen++
	v.core.raiseIRQ(virtioIntConfig)
}

func (v *Mem) deviceID() uint32 { return MemDeviceID }
func (v *Mem) features() uint64 { return 0 }
func (v *Mem) numQueues() int   { return 1 }

func (v *Mem) reset() {
	clear(v.plugged)
	v.pluggedSize = 0
}

func (v *Mem) configRead(off uint64, p []byte) {
	var config [memConfigSize]byte
	binary.LittleEndian.PutUint64(config[0:], v.blockSize)
	// node_id remains zero and is ignored because VIRTIO_MEM_F_ACPI_PXM is
	// not offered. Bytes 10..15 are the specified padding.
	binary.LittleEndian.PutUint64(config[16:], v.addr)
	binary.LittleEndian.PutUint64(config[24:], v.regionSize)
	binary.LittleEndian.PutUint64(config[32:], v.regionSize) // usable_region_size
	binary.LittleEndian.PutUint64(config[40:], v.pluggedSize)
	binary.LittleEndian.PutUint64(config[48:], v.requestedSize)
	if off >= uint64(len(config)) {
		clear(p)
		return
	}
	n := copy(p, config[off:])
	clear(p[n:])
}

// All virtio-mem configuration fields are device-owned.
func (v *Mem) configWrite(off uint64, p []byte) {}

func (v *Mem) handleQueue(qn int) {
	q := &v.core.queues[qn]
	for {
		head, chain, ok := v.core.availChain(qn)
		if !ok {
			return
		}
		readable, writable := splitChain(chain)
		request, err := v.core.readChains(readable)
		var response [memResponseSize]byte
		if err != nil {
			binary.LittleEndian.PutUint16(response[:], memRespError)
		} else {
			response = v.handleRequest(request)
		}
		written, _ := v.core.writeChains(writable, response[:])
		v.core.pushUsed(q, head, written)
	}
}

func (v *Mem) handleRequest(request []byte) (response [memResponseSize]byte) {
	responseType := uint16(memRespError)
	defer func() { binary.LittleEndian.PutUint16(response[:], responseType) }()
	if len(request) < memRequestSize {
		return response
	}
	typeID := binary.LittleEndian.Uint16(request[0:])
	if typeID == memReqUnplugAll {
		v.reset()
		responseType = memRespACK
		return response
	}
	if typeID != memReqPlug && typeID != memReqUnplug && typeID != memReqState {
		return response
	}

	addr := binary.LittleEndian.Uint64(request[8:])
	count := uint64(binary.LittleEndian.Uint16(request[16:]))
	if count == 0 || addr < v.addr || addr%v.blockSize != 0 {
		return response
	}
	first := (addr - v.addr) / v.blockSize
	if first >= uint64(len(v.plugged)) || count > uint64(len(v.plugged))-first {
		return response
	}

	switch typeID {
	case memReqPlug:
		var newBlocks uint64
		for _, plugged := range v.plugged[first : first+count] {
			if !plugged {
				newBlocks++
			}
		}
		if newBlocks > (v.requestedSize-v.pluggedSize)/v.blockSize {
			responseType = memRespNACK
			return response
		}
		for index := first; index < first+count; index++ {
			v.plugged[index] = true
		}
		v.pluggedSize += newBlocks * v.blockSize
		responseType = memRespACK
	case memReqUnplug:
		var oldBlocks uint64
		for index := first; index < first+count; index++ {
			if v.plugged[index] {
				oldBlocks++
				v.plugged[index] = false
			}
		}
		v.pluggedSize -= oldBlocks * v.blockSize
		responseType = memRespACK
	case memReqState:
		plugged := 0
		for _, state := range v.plugged[first : first+count] {
			if state {
				plugged++
			}
		}
		state := uint16(memStateMixed)
		if plugged == 0 {
			state = memStateUnplugged
		} else if plugged == int(count) {
			state = memStatePlugged
		}
		binary.LittleEndian.PutUint16(response[8:], state)
		responseType = memRespACK
	}
	return response
}

func (v *Mem) maxChainBytes(qn int) uint64 { return memRequestSize + memResponseSize }
func (v *Mem) setCore(c *Core)             { v.core = c }
