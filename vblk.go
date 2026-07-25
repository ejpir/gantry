package main

import (
	"encoding/binary"
	"fmt"
	"os"
)

// virtio-blk (device ID 2), file-backed. The boot -rootfs is exposed
// read-only (VIRTIO_BLK_F_RO); extra -disk images are writable and support
// WRITE (T_OUT) and FLUSH, which is what the sbx-style ext4 rwlayer needs.
const (
	virtioBlkDeviceID = 2

	virtioBlkTIn    = 0
	virtioBlkTOut   = 1
	virtioBlkTFlush = 4
	virtioBlkTGetID = 8

	virtioBlkSOK          = 0
	virtioBlkSIOErr       = 1
	virtioBlkSUnsupported = 2

	virtioBlkFRO    = 5 // feature: device is read-only
	virtioBlkFFlush = 9 // feature: cache flush command
)

type virtioBlk struct {
	file     *os.File
	core     *virtioMMIOCore
	size     uint64
	writable bool
	debugLog bool
}

func (b *virtioBlk) logf(format string, a ...any) {
	if b.debugLog {
		fmt.Printf("[blk %s] "+format+"\n", append([]any{b.core.name}, a...)...)
	}
}

func newVirtioBlk(path string, writable bool) (*virtioBlk, error) {
	flag := os.O_RDONLY
	if writable {
		flag = os.O_RDWR
	}
	f, err := os.OpenFile(path, flag, 0)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	return &virtioBlk{file: f, size: uint64(fi.Size()), writable: writable,
		debugLog: envOr("GANTRY_DEBUG_BLK", "MINIVM_DEBUG_BLK") != ""}, nil
}

func (b *virtioBlk) deviceID() uint32 { return virtioBlkDeviceID }
func (b *virtioBlk) features() uint64 {
	if b.writable {
		return 1 << virtioBlkFFlush
	}
	return 1 << virtioBlkFRO
}
func (b *virtioBlk) numQueues() int { return 1 }
func (b *virtioBlk) reset()         {}

// virtio_blk_config: capacity @0 (u64), size_max @8, seg_max @12,
// geometry @16, blk_size @20.
func (b *virtioBlk) configRead(off uint64, p []byte) {
	cfg := make([]byte, 64)
	binary.LittleEndian.PutUint64(cfg[0:], b.size/512) // capacity in sectors
	binary.LittleEndian.PutUint32(cfg[8:], 0x20000)    // size_max 128KiB
	binary.LittleEndian.PutUint32(cfg[12:], 32)        // seg_max
	binary.LittleEndian.PutUint32(cfg[20:], 512)       // blk_size
	if off < uint64(len(cfg)) {
		copy(p, cfg[off:])
	}
}

func (b *virtioBlk) configWrite(off uint64, p []byte) {}

func (b *virtioBlk) handleQueue(qn int) {
	q := &b.core.queues[qn]
	for {
		head, chain, ok := b.core.availChain(q)
		if !ok {
			return
		}
		b.logf("notify: head=%d chainlen=%d", head, len(chain))
		out, in := splitChain(chain)
		if len(out) == 0 || len(in) == 0 {
			// a malformed chain must still be returned to the guest —
			// dropping it leaks the descriptor and wedges the driver
			b.core.pushUsed(q, head, 0)
			continue
		}
		hdr, err := b.core.readChains(out[:1])
		if err != nil || len(hdr) < 16 {
			b.core.pushUsed(q, head, 0)
			continue
		}
		reqType := binary.LittleEndian.Uint32(hdr[0:])
		sector := binary.LittleEndian.Uint64(hdr[8:])

		var status byte = virtioBlkSOK
		var written uint32

		switch reqType {
		case virtioBlkTIn: // read
			dataLen := uint32(0)
			for _, d := range in[:len(in)-1] { // last "in" desc is the status byte
				dataLen += d.len
			}
			buf := make([]byte, dataLen)
			// guard sector before the *512 to rule out uint64 overflow
			if sector > uint64(b.size)>>9 {
				status = virtioBlkSIOErr
			} else if off := int64(sector * 512); off+int64(dataLen) <= int64(b.size) {
				if _, err := b.file.ReadAt(buf, off); err != nil {
					status = virtioBlkSIOErr
				}
			} else {
				status = virtioBlkSIOErr
			}
			if status == virtioBlkSOK {
				if n, err := b.core.writeChains(in[:len(in)-1], buf); err == nil {
					written = n
				} else {
					status = virtioBlkSIOErr
				}
			}
		case virtioBlkTOut: // write
			if !b.writable {
				status = virtioBlkSUnsupported
				break
			}
			dataLen := uint32(0)
			for _, d := range out[1:] { // device-readable data after the header
				dataLen += d.len
			}
			buf, err := b.core.readChains(out[1:])
			if err != nil || uint32(len(buf)) != dataLen {
				status = virtioBlkSIOErr
				break
			}
			if sector > uint64(b.size)>>9 {
				status = virtioBlkSIOErr // also rules out *512 overflow
			} else if off := int64(sector * 512); off+int64(dataLen) > int64(b.size) {
				status = virtioBlkSIOErr // fixed-size image, no growth
			} else if _, err := b.file.WriteAt(buf, off); err != nil {
				status = virtioBlkSIOErr
			}
		case virtioBlkTFlush:
			if b.writable {
				if err := b.file.Sync(); err != nil {
					status = virtioBlkSIOErr
				}
			}
			// read-only backend: nothing to flush
		case virtioBlkTGetID:
			id := make([]byte, 20)
			copy(id, "gantry-blk")
			if n, err := b.core.writeChains(in[:len(in)-1], id); err == nil {
				written = n
			}
		default:
			status = virtioBlkSUnsupported
		}

		b.logf("req type=%d sector=%d -> status=%d written=%d", reqType, sector, status, written)
		// status byte lives in the last descriptor of the chain
		st := in[len(in)-1]
		if err := b.core.mem.writeAt(st.addr, []byte{status}); err != nil {
			b.logf("status write: %v", err)
		}
		written++
		b.core.pushUsed(q, head, written)
	}
}
