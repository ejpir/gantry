//go:build linux || darwin || windows

package virtio

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"github.com/ejpir/gantry/internal/fusewire"

	"github.com/hanwen/go-fuse/v2/fuse"
)

const (
	virtioFSDeviceID = 26
	virtioFSHiprioQ  = 0
	virtioFSRequestQ = 1
	fsMaxChainBytes  = 256 << 10
)

// FS is a host-path-neutral virtio-fs frontend. It does not own handler; the
// component that created the handler controls its lifetime explicitly.
type FS struct {
	core          *Core
	tag           string
	handler       fusewire.Handler
	owner         io.Closer
	notifySource  fusewire.NotificationSource
	notifications *fsNotificationQueue
	verbose       bool

	// Core serializes queue dispatch, so request vectors and their backing
	// storage can be reused without pooling or cross-goroutine ownership.
	inputVectors  [virtqMaxChainDescriptors][]byte
	outputVectors [virtqMaxChainDescriptors][]byte
	inputStorage  []byte
	outputStorage []byte
	inputCount    int
	outputCount   int
}

// NewFS constructs a frontend. If owner is non-nil, the device closes it when
// detached; a nil owner leaves lifetime control with the caller.
func NewFS(tag string, handler fusewire.Handler, owner io.Closer) (*FS, error) {
	if tag == "" || len(tag) > FSTagLen {
		return nil, fmt.Errorf("virtio-fs: tag must contain 1..%d bytes", FSTagLen)
	}
	if handler == nil {
		return nil, fmt.Errorf("virtio-fs: nil request handler")
	}
	notifySource, _ := handler.(fusewire.NotificationSource)
	return &FS{
		tag:          tag,
		handler:      handler,
		owner:        owner,
		notifySource: notifySource,
		verbose:      os.Getenv("GANTRY_DEBUG_FS") != "",
	}, nil
}

func (v *FS) Tag() string      { return v.tag }
func (v *FS) deviceID() uint32 { return virtioFSDeviceID }
func (v *FS) features() uint64 {
	if v.notifySource != nil {
		return virtioFSFGantryNotification
	}
	return 0
}
func (v *FS) numQueues() int { return virtioFSQueueCount }
func (v *FS) reset() {
	if v.notifications != nil {
		v.notifications.reset()
	}
}
func (v *FS) setCore(c *Core) {
	v.core = c
	v.notifications = newFSNotificationQueue(c, v.notifySource)
}

func (v *FS) Close() error {
	if v.notifications != nil {
		v.notifications.close()
	}
	if v.owner == nil {
		return nil
	}
	return v.owner.Close()
}

func (v *FS) configRead(off uint64, p []byte) {
	var cfg [FSTagLen + 4]byte
	copy(cfg[:FSTagLen], []byte(v.tag))
	binary.LittleEndian.PutUint32(cfg[FSTagLen:], 1)
	if off < uint64(len(cfg)) {
		copy(p, cfg[off:])
	}
}

func (v *FS) configWrite(off uint64, p []byte) {}

func (v *FS) logf(format string, args ...any) {
	if v.verbose {
		fmt.Printf("[fs %s] "+format+"\n", append([]any{v.tag}, args...)...)
	}
}

func (v *FS) handleQueue(qn int) {
	if qn == virtioFSNotificationQ {
		if v.core.driverFeat&virtioFSFGantryNotification != 0 {
			v.notifications.acceptAvailable()
		}
		return
	}
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
		if !fusewire.ValidRequest(in) {
			v.logf("rejecting malformed request descriptor shape")
			v.core.pushUsed(q, head, 0)
			continue
		}
		out := v.responseIOV(writable)

		n, status := v.handler.HandleRequest(in, out)
		if status != fuse.OK {
			v.logf("protocol request failed: %v", status)
			n = fusewire.WriteError(in, out, status)
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

func (v *FS) readIOV(ds []desc) ([][]byte, error) {
	out := buildIOV(ds, &v.inputVectors, &v.inputStorage, &v.inputCount)
	for i, d := range ds {
		if err := v.core.mem.readAt(d.addr, out[i]); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (v *FS) responseIOV(ds []desc) [][]byte {
	out := buildIOV(ds, &v.outputVectors, &v.outputStorage, &v.outputCount)
	clear(v.outputStorage)
	return out
}

func buildIOV(ds []desc, vectors *[virtqMaxChainDescriptors][]byte, storage *[]byte, previous *int) [][]byte {
	total := 0
	for _, d := range ds {
		total += int(d.len)
	}
	if cap(*storage) < total {
		*storage = make([]byte, total)
	} else {
		*storage = (*storage)[:total]
	}

	offset := 0
	for i, d := range ds {
		next := offset + int(d.len)
		vectors[i] = (*storage)[offset:next]
		offset = next
	}
	for i := len(ds); i < *previous; i++ {
		vectors[i] = nil
	}
	*previous = len(ds)
	return vectors[:len(ds)]
}

func (v *FS) writeIOV(ds []desc, bufs [][]byte, limit int) (uint32, error) {
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

func (v *FS) maxChainBytes(qn int) uint64 {
	if qn == virtioFSNotificationQ {
		return fusewire.MaxNotificationBytes
	}
	return fsMaxChainBytes
}

var _ Device = (*FS)(nil)
