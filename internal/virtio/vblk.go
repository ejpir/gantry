package virtio

import (
	"encoding/binary"
	"fmt"
	"os"

	"github.com/ejpir/gantry/internal/gutil"
)

// virtio-blk (device ID 2), file-backed. The boot -rootfs is exposed
// read-only (VIRTIO_BLK_F_RO); extra -disk images are writable and support
// WRITE (T_OUT) and FLUSH, which is what the ext4 rwlayer needs.
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

// BlkBackend is the fixed-size storage capability behind a virtio-blk
// device. Split VMMs use a brokered implementation so their untrusted worker
// never receives a writable host-file descriptor.
type BlkBackend interface {
	ReadAt([]byte, int64) (int, error)
	WriteAt([]byte, int64) (int, error)
	Sync() error
	Close() error
	Name() string
	Size() uint64
}

type fileBlkBackend struct {
	file *os.File
	size uint64
}

func (backend *fileBlkBackend) ReadAt(buffer []byte, offset int64) (int, error) {
	return backend.file.ReadAt(buffer, offset)
}

func (backend *fileBlkBackend) WriteAt(buffer []byte, offset int64) (int, error) {
	return backend.file.WriteAt(buffer, offset)
}

func (backend *fileBlkBackend) Sync() error  { return backend.file.Sync() }
func (backend *fileBlkBackend) Close() error { return backend.file.Close() }
func (backend *fileBlkBackend) Name() string { return backend.file.Name() }
func (backend *fileBlkBackend) Size() uint64 { return backend.size }

type Blk struct {
	backend  BlkBackend
	lock     *os.File // held for the VM's lifetime on writable images
	core     *Core
	size     uint64
	writable bool
	debugLog bool
	data     []byte
}

func (b *Blk) logf(format string, a ...any) {
	if b.debugLog {
		fmt.Printf("[blk %s] "+format+"\n", append([]any{b.core.name}, a...)...)
	}
}

// NewBlk opens a disk image. Writable images are exclusively locked for the
// caller's lifetime: two live VMs sharing one ext4 means two guest kernels with
// independent page caches and allocators writing the same block bitmaps —
// the silent corruption behind "stale file handle" overlay failures.
// The lock turns that into an immediate, honest error.
func NewBlk(path string, writable bool) (*Blk, error) {
	flag := os.O_RDONLY
	if writable {
		flag = os.O_RDWR
	}
	f, err := os.OpenFile(path, flag, 0)
	if err != nil {
		return nil, err
	}
	b, err := NewBlkFile(f, writable)
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return b, nil
}

// NewBlkFile attaches an already-open disk image. The descriptor (not the
// path) is authoritative. Monolithic VMMs acquire the writable lock here;
// split VMMs use NewBlkFilePrelocked because their trusted supervisor must
// remain the lock owner.
func NewBlkFile(f *os.File, writable bool) (*Blk, error) {
	return newBlkFile(f, writable, false)
}

// NewBlkFilePrelocked attaches a writable disk whose exclusive lock is held
// by the trusted supervisor process. The split VMM child must not acquire the
// lock itself: the supervisor holds it on a private open file description
// (gutil.TryLockPrivate) that the child never inherits and cannot release.
func NewBlkFilePrelocked(f *os.File, writable bool) (*Blk, error) {
	return newBlkFile(f, writable, true)
}

func newBlkFile(f *os.File, writable, prelocked bool) (*Blk, error) {
	b := &Blk{debugLog: os.Getenv("GANTRY_DEBUG_BLK") != ""}
	if writable && !prelocked {
		lock, err := gutil.TryLockFD(f)
		if err != nil {
			return nil, fmt.Errorf("%s is already attached to another gantry VM (a writable disk cannot be shared)", f.Name())
		}
		b.lock = lock
	}
	fi, err := f.Stat()
	if err != nil {
		if b.lock != nil {
			_ = b.lock.Close()
		}
		return nil, err
	}
	b.backend = &fileBlkBackend{file: f, size: uint64(fi.Size())}
	b.size = uint64(fi.Size())
	b.writable = writable
	return b, nil
}

// NewBlkBackend attaches an already bounded storage capability. The caller
// retains ownership on error; Blk owns and closes it after a successful call.
// Writable remote backends are prelocked by their trusted broker.
func NewBlkBackend(backend BlkBackend, writable bool) (*Blk, error) {
	if backend == nil {
		return nil, fmt.Errorf("nil block backend")
	}
	size := backend.Size()
	if size == 0 || size > uint64(^uint64(0)>>1) {
		return nil, fmt.Errorf("block backend %s has invalid size %d", backend.Name(), size)
	}
	return &Blk{
		backend: backend, size: size, writable: writable,
		debugLog: os.Getenv("GANTRY_DEBUG_BLK") != "",
	}, nil
}

// Close flushes a writable image to the host filesystem and releases the
// image and the write lock. The guest sync at VM shutdown makes the
// guest's view coherent; this host-side Sync makes sure the VMM's own
// writes reached the host's storage too (review finding 5: VM stop used
// to be a power cut for persistent disks).
func (b *Blk) Close() error {
	var err error
	if b.backend != nil {
		if b.writable {
			err = b.backend.Sync()
		}
		if cerr := b.backend.Close(); err == nil {
			err = cerr
		}
	}
	if b.lock != nil {
		_ = b.lock.Close()
	}
	return err
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
	var cfg [64]byte
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
		head, chain, ok := b.core.availChain(qn)
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
			buf := b.resizeData(int(dataLen))
			// guard sector before the *512 to rule out uint64 overflow
			if sector > uint64(b.size)>>9 {
				status = BlkSIOErr
			} else if off := int64(sector * 512); off+int64(dataLen) <= int64(b.size) {
				if _, err := b.backend.ReadAt(buf, off); err != nil {
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
			} else if _, err := b.backend.WriteAt(buf, off); err != nil {
				status = BlkSIOErr
			}
		case BlkTFlush:
			if b.writable {
				if err := b.backend.Sync(); err != nil {
					status = BlkSIOErr
				}
			}
			// read-only backend: nothing to flush
		case BlkTGetID:
			var id [20]byte
			copy(id[:], "gantry-blk")
			if n, err := b.core.writeChains(in[:len(in)-1], id[:]); err == nil {
				written = n
			}
		default:
			status = BlkSUnsupported
		}

		b.logf("req type=%d sector=%d -> status=%d written=%d", reqType, sector, status, written)
		// status byte lives in the last descriptor of the chain
		st := in[len(in)-1]
		statusBuffer := [1]byte{status}
		if err := b.core.mem.writeAt(st.addr, statusBuffer[:]); err != nil {
			b.logf("status write: %v", err)
		}
		written++
		b.core.pushUsed(q, head, written)
	}
}

func (b *Blk) resizeData(size int) []byte {
	if cap(b.data) < size {
		b.data = make([]byte, size)
	} else {
		b.data = b.data[:size]
	}
	return b.data
}

// blkMaxChainBytes caps one request chain at seg_max (32) × size_max
// (128 KiB — both advertised in the device config) plus header/status
// slack. Anything larger is a malicious guest fishing for a
// guest-RAM-sized host allocation (review finding 2).
const blkMaxChainBytes = 32*(128<<10) + 4096

func (b *Blk) maxChainBytes(qn int) uint64 { return blkMaxChainBytes }

func (v *Blk) setCore(c *Core) { v.core = c }

// Size reports the image size in bytes (device config + logs).
func (b *Blk) Size() uint64 { return b.size }
