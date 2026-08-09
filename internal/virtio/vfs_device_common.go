//go:build linux || darwin || windows

package virtio

import (
	"encoding/binary"
	"fmt"

	"github.com/hanwen/go-fuse/v2/fuse"
)

// fsTransportDevice is the host-path-neutral half of a virtio-fs device. It
// owns only the virtio-mmio frontend and a FUSE request handler. The handler
// may be local (ShareHub) or an IPC proxy (ShareHubProxy).
//
// Keeping this type separate from ShareHub is the security seam that lets a
// VMM worker emulate the virtqueue without receiving any host share roots.
type fsTransportDevice struct {
	core    *Core
	tag     string
	handler fuseRequestHandler
	verbose bool
}

func newFSTransportDevice(tag string, handler fuseRequestHandler, verbose bool) *fsTransportDevice {
	return &fsTransportDevice{tag: tag, handler: handler, verbose: verbose}
}

func (v *fsTransportDevice) deviceID() uint32 { return virtioFSDeviceID }
func (v *fsTransportDevice) features() uint64 { return 0 }
func (v *fsTransportDevice) numQueues() int   { return 2 }
func (v *fsTransportDevice) reset()           {}
func (v *fsTransportDevice) setCore(c *Core)  { v.core = c }

func (v *fsTransportDevice) configRead(off uint64, p []byte) {
	var cfg [FSTagLen + 4]byte
	copy(cfg[:FSTagLen], []byte(v.tag))
	binary.LittleEndian.PutUint32(cfg[FSTagLen:], 1)
	if off < uint64(len(cfg)) {
		copy(p, cfg[off:])
	}
}

func (v *fsTransportDevice) configWrite(off uint64, p []byte) {}

func (v *fsTransportDevice) logf(format string, args ...any) {
	if v.verbose {
		fmt.Printf("[fs %s] "+format+"\n", append([]any{v.tag}, args...)...)
	}
}

func (v *fsTransportDevice) handleQueue(qn int) {
	if qn != virtioFSHiprioQ && qn != virtioFSRequestQ {
		return
	}
	q := &v.core.queues[qn]
	for {
		head, chain, ok := v.core.availChain(qn)
		if !ok {
			return
		}
		readable, writable := splitChain(chain)
		in, err := v.readIOV(readable)
		if err != nil {
			v.logf("read request descriptors: %v", err)
			v.core.pushUsed(q, head, 0)
			continue
		}
		out := make([][]byte, len(writable))
		for i, d := range writable {
			out[i] = make([]byte, d.len)
		}

		n, status := v.handler.HandleRequest(in, out)
		if status != fuse.OK {
			v.logf("protocol request failed: %v", status)
			n = v.writeProtocolError(in, out, status)
		}
		if len(writable) == 0 {
			n = 0
		}
		if n < 0 {
			n = 0
		}
		capacity := 0
		for _, b := range out {
			capacity += len(b)
		}
		if n > capacity {
			n = capacity
		}
		written, err := v.writeIOV(writable, out, n)
		if err != nil {
			v.logf("write response descriptors: %v", err)
			written = 0
		}
		v.core.pushUsed(q, head, written)
	}
}

func (v *fsTransportDevice) readIOV(ds []desc) ([][]byte, error) {
	out := make([][]byte, len(ds))
	for i, d := range ds {
		out[i] = make([]byte, d.len)
		if err := v.core.mem.readAt(d.addr, out[i]); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (v *fsTransportDevice) writeIOV(ds []desc, bufs [][]byte, limit int) (uint32, error) {
	var written uint32
	remaining := limit
	for i, d := range ds {
		if remaining <= 0 || i >= len(bufs) {
			break
		}
		b := bufs[i]
		if len(b) > remaining {
			b = b[:remaining]
		}
		if len(b) > int(d.len) {
			b = b[:d.len]
		}
		if err := v.core.mem.writeAt(d.addr, b); err != nil {
			return written, err
		}
		written += uint32(len(b))
		remaining -= len(b)
	}
	return written, nil
}

func (v *fsTransportDevice) writeProtocolError(in, out [][]byte, status fuse.Status) int {
	if len(out) == 0 || len(out[0]) < 16 {
		return 0
	}
	buf := out[0][:16]
	binary.LittleEndian.PutUint32(buf[0:4], 16)
	binary.LittleEndian.PutUint32(buf[4:8], uint32(-int32(status)))
	if len(in) > 0 && len(in[0]) >= 16 {
		copy(buf[8:16], in[0][8:16])
	}
	return 16
}

func (v *fsTransportDevice) maxChainBytes(qn int) uint64 { return fsMaxChainBytes }

var _ Device = (*fsTransportDevice)(nil)
