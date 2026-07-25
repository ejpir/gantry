package virtio

import (
	"encoding/binary"
	"fmt"
	"gantry/internal/gutil"
	"os"
)

// virtio-blk (device ID 2), file-backed. The boot -rootfs is exposed
// read-only (VIRTIO_BLK_F_RO); extra -disk images are writable and support
// WRITE (T_OUT) and FLUSH, which is what the sbx-style ext4 rwlayer needs.
const (
	BlkDeviceID = 2

	BlkTIn    = 0
	BlkTOut   = 1
	BlkTFlush = 4
	BlkTGetID = 8

	BlkSOK          = 0
	BlkSIOErr       = 1
	BlkSUnsupported = 2

	BlkFRO    = 5 // feature: device is read-only
	BlkFFlush = 9 // feature: cache flush command
)

type Blk struct {
	file     *os.File
	core     *Core
	size     uint64
	writable bool
	debugLog bool
}

func (b *Blk) logf(format string, a ...any) {
	if b.debugLog {
		fmt.Printf("[blk %s] "+format+"\n", append([]any{b.core.name}, a...)...)
	}
}

func NewBlk(path string, writable bool) (*Blk, error) {
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
	return &Blk{file: f, size: uint64(fi.Size()), writable: writable,
		debugLog: gutil.EnvOr("GANTRY_DEBUG_BLK", "MINIVM_DEBUG_BLK") != ""}, nil
}

func (b *Blk) deviceID() uint32 { return BlkDeviceID }
func (b *Blk) features() uint64 {
	if b.writable {
		return 1 << BlkFFlush
	}
	return 1 << BlkFRO
}
func (b *Blk) numQueues() int { return 1 }
func (b *Blk) reset()         {}

// virtio_blk_config: capacity @0 (u64), size_max @8, seg_max @12,
// geometry @16, blk_size @20.
func (b *Blk) configRead(off uint64, p []byte) {
	cfg := make([]byte, 64)
	binary.LittleEndian.PutUint64(cfg[0:], b.size/512) // capacity in sectors
	binary.LittleEndian.PutUint32(cfg[8:], 0x20000)    // size_max 128KiB
	binary.LittleEndian.PutUint32(cfg[12:], 32)        // seg_max
	binary.LittleEndian.PutUint32(cfg[20:], 512)       // blk_size
	if off < uint64(len(cfg)) {
		copy(p, cfg[off:])
	}
}

func (b *Blk) configWrite(off uint64, p []byte) {}

func (b *Blk) handleQueue(qn int) {
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

		var status byte = BlkSOK
		var written uint32

		switch reqType {
		case BlkTIn: // read
			dataLen := uint32(0)
			for _, d := range in[:len(in)-1] { // last "in" desc is the status byte
				dataLen += d.len
			}
			buf := make([]byte, dataLen)
			// guard sector before the *512 to rule out uint64 overflow
			if sector > uint64(b.size)>>9 {
				status = BlkSIOErr
			} else if off := int64(sector * 512); off+int64(dataLen) <= int64(b.size) {
				if _, err := b.file.ReadAt(buf, off); err != nil {
					status = BlkSIOErr
				}
			} else {
				status = BlkSIOErr
			}
			if status == BlkSOK {
				if n, err := b.core.writeChains(in[:len(in)-1], buf); err == nil {
					written = n
				} else {
					status = BlkSIOErr
				}
			}
		case BlkTOut: // write
			if !b.writable {
				status = BlkSUnsupported
				break
			}
			dataLen := uint32(0)
			for _, d := range out[1:] { // device-readable data after the header
				dataLen += d.len
			}
			buf, err := b.core.readChains(out[1:])
			if err != nil || uint32(len(buf)) != dataLen {
				status = BlkSIOErr
				break
			}
			if sector > uint64(b.size)>>9 {
				status = BlkSIOErr // also rules out *512 overflow
			} else if off := int64(sector * 512); off+int64(dataLen) > int64(b.size) {
				status = BlkSIOErr // fixed-size image, no growth
			} else if _, err := b.file.WriteAt(buf, off); err != nil {
				status = BlkSIOErr
			}
		case BlkTFlush:
			if b.writable {
				if err := b.file.Sync(); err != nil {
					status = BlkSIOErr
				}
			}
			// read-only backend: nothing to flush
		case BlkTGetID:
			id := make([]byte, 20)
			copy(id, "gantry-blk")
			if n, err := b.core.writeChains(in[:len(in)-1], id); err == nil {
				written = n
			}
		default:
			status = BlkSUnsupported
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

func (v *Blk) setCore(c *Core) { v.core = c }

// Size reports the image size in bytes (device config + logs).
func (b *Blk) Size() uint64 { return b.size }
