//go:build linux || darwin

package virtio

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"syscall"

	"github.com/ejpir/gantry/internal/fusewire"
)

const (
	vhostUserSetFeatures         = uint32(2)
	vhostUserSetOwner            = uint32(3)
	vhostUserSetVringNum         = uint32(8)
	vhostUserSetVringAddr        = uint32(9)
	vhostUserSetVringBase        = uint32(10)
	vhostUserSetVringKick        = uint32(12)
	vhostUserSetVringCall        = uint32(13)
	vhostUserSetProtocolFeatures = uint32(16)
	vhostUserSetVringEnable      = uint32(18)
	vhostUserAddMemReg           = uint32(37)

	vhostUserVersion   = uint32(1)
	vhostUserReply     = uint32(1 << 2)
	vhostUserNeedReply = uint32(1 << 3)

	vhostProtocolReplyAck         = uint64(1 << 3)
	vhostProtocolConfigureMemSlot = uint64(1 << 15)
	vhostRingIndirectDesc         = uint64(1 << 28)
	vhostRingEventIdx             = uint64(1 << 29)
	vhostProtocolFeatures         = uint64(1 << 30)
	vhostVersion1                 = uint64(1 << 32)
)

// VhostQueueFiles are one queue's two unidirectional doorbells. The frontend
// keeps KickWrite and CallRead. KickRead and CallWrite are transferred to the
// backend during setup and then closed locally.
type VhostQueueFiles struct {
	KickRead  *os.File
	KickWrite *os.File
	CallRead  *os.File
	CallWrite *os.File
}

// VhostEndpoint is the setup-only vhost-user connection and queue doorbell
// table received by the VMM worker. NewDevice consumes it.
type VhostEndpoint struct {
	control *net.UnixConn
	queues  []VhostQueueFiles
	one     sync.Once
}

func NewVhostEndpoint(control net.Conn, queues []VhostQueueFiles) (*VhostEndpoint, error) {
	unixConn, ok := control.(*net.UnixConn)
	if !ok || unixConn == nil {
		return nil, fmt.Errorf("vhost-fs: control channel is %T, want Unix connection", control)
	}
	if len(queues) != virtioFSQueueCount {
		return nil, fmt.Errorf("vhost-fs: got %d queues, want %d", len(queues), virtioFSQueueCount)
	}
	for index, queue := range queues {
		if queue.KickRead == nil || queue.KickWrite == nil || queue.CallRead == nil || queue.CallWrite == nil {
			return nil, fmt.Errorf("vhost-fs: queue %d has an incomplete doorbell table", index)
		}
	}
	return &VhostEndpoint{control: unixConn, queues: queues}, nil
}

func (e *VhostEndpoint) Close() error {
	if e == nil {
		return nil
	}
	var errs []error
	if e.control != nil {
		errs = append(errs, e.control.Close())
		e.control = nil
	}
	for index := range e.queues {
		queue := &e.queues[index]
		for _, file := range []*os.File{queue.KickRead, queue.KickWrite, queue.CallRead, queue.CallWrite} {
			if file != nil {
				errs = append(errs, file.Close())
			}
		}
		*queue = VhostQueueFiles{}
	}
	return errors.Join(errs...)
}

// NewDevice consumes the endpoint and shared-memory descriptor on success.
func (e *VhostEndpoint) NewDevice(tag string, memory *os.File, guestBase, memorySize uint64) (Device, error) {
	if e == nil || e.control == nil {
		return nil, fmt.Errorf("vhost-fs: unavailable endpoint")
	}
	if memory == nil {
		return nil, fmt.Errorf("vhost-fs: shared guest RAM is required")
	}
	var device *VhostFS
	consumed := false
	e.one.Do(func() {
		device = &VhostFS{
			tag:        tag,
			control:    e.control,
			memory:     memory,
			guestBase:  guestBase,
			memorySize: memorySize,
			queues:     e.queues,
		}
		e.control = nil
		e.queues = nil
		consumed = true
	})
	if !consumed {
		return nil, fmt.Errorf("vhost-fs: endpoint already consumed")
	}
	return device, nil
}

type vhostQueueSnapshot struct {
	num                 uint32
	desc, avail, used   uint64
	configured, started bool
}

// VhostFS is the virtio-mmio frontend retained in the VMM process. Queue data
// is never copied through control: the backend maps guest RAM and consumes the
// rings directly. The only hot-path operations here are eight-byte doorbells.
type VhostFS struct {
	core       *Core
	tag        string
	control    *net.UnixConn
	memory     *os.File
	guestBase  uint64
	memorySize uint64
	queues     []VhostQueueFiles
	configured [virtioFSQueueCount]vhostQueueSnapshot

	setupOnce sync.Once
	setupErr  error
	callWG    sync.WaitGroup
	closeOnce sync.Once
	closeErr  error
}

func (v *VhostFS) deviceID() uint32 { return virtioFSDeviceID }
func (v *VhostFS) features() uint64 {
	// EVENT_IDX lets the driver suppress redundant completion interrupts while
	// polling or draining a batch. Shared-ring barriers and cross-process
	// rearming are covered by the vhost transport stress tests.
	return virtioFSFGantryNotification | vhostRingIndirectDesc | vhostRingEventIdx
}
func (v *VhostFS) numQueues() int  { return virtioFSQueueCount }
func (v *VhostFS) setCore(c *Core) { v.core = c }
func (v *VhostFS) maxChainBytes(queue int) uint64 {
	if queue == virtioFSNotificationQ {
		return fusewire.MaxNotificationBytes
	}
	return fsMaxChainBytes
}
func (v *VhostFS) configWrite(uint64, []byte) {}

func (v *VhostFS) configRead(off uint64, p []byte) {
	var cfg [FSTagLen + 4]byte
	copy(cfg[:FSTagLen], []byte(v.tag))
	binary.LittleEndian.PutUint32(cfg[FSTagLen:], 1)
	if off < uint64(len(cfg)) {
		copy(p, cfg[off:])
	}
}

func (v *VhostFS) reset() {
	for index := range v.configured {
		started := v.configured[index].started
		v.configured[index] = vhostQueueSnapshot{started: started}
	}
}

func (v *VhostFS) handleQueue(qn int) {
	if qn < 0 || qn >= len(v.queues) {
		return
	}
	v.setupOnce.Do(func() { v.setupErr = v.setup() })
	if v.setupErr != nil {
		return
	}
	q := &v.core.queues[qn]
	if !q.ready || !q.numValid() {
		return
	}
	snapshot := &v.configured[qn]
	if !snapshot.configured || snapshot.num != q.num || snapshot.desc != q.descAddr ||
		snapshot.avail != q.availAddr || snapshot.used != q.usedAddr {
		if err := v.configureQueue(qn, q); err != nil {
			v.setupErr = err
			fmt.Fprintf(os.Stderr, "vhost-fs: configure queue %d: %v\n", qn, err)
			return
		}
	}
	var doorbell [8]byte
	doorbell[0] = 1
	if _, err := v.queues[qn].KickWrite.Write(doorbell[:]); err != nil && !errors.Is(err, syscall.EAGAIN) {
		v.setupErr = fmt.Errorf("kick queue %d: %w", qn, err)
		fmt.Fprintln(os.Stderr, "vhost-fs:", v.setupErr)
	}
}

func (v *VhostFS) setup() error {
	if v.core == nil || v.control == nil || v.memory == nil {
		return fmt.Errorf("incomplete frontend")
	}
	features := v.core.driverFeat | vhostProtocolFeatures | vhostVersion1
	if err := v.request(vhostUserSetOwner, nil, -1); err != nil {
		return err
	}
	if err := v.request(vhostUserSetFeatures, u64Payload(features), -1); err != nil {
		return err
	}
	protocol := vhostProtocolReplyAck | vhostProtocolConfigureMemSlot
	if err := v.request(vhostUserSetProtocolFeatures, u64Payload(protocol), -1); err != nil {
		return err
	}
	memory := make([]byte, 40)
	// VhostUserMemRegMsg: padding + one VhostUserMemoryRegion. DriverAddr is
	// deliberately the guest-physical base, so vring addresses need no host
	// pointer disclosure or translation in the frontend.
	binary.LittleEndian.PutUint64(memory[8:16], v.guestBase)
	binary.LittleEndian.PutUint64(memory[16:24], v.memorySize)
	binary.LittleEndian.PutUint64(memory[24:32], v.guestBase)
	if err := v.request(vhostUserAddMemReg, memory, int(v.memory.Fd())); err != nil {
		return err
	}
	if err := v.memory.Close(); err != nil {
		return fmt.Errorf("close transferred shared RAM: %w", err)
	}
	v.memory = nil

	for index := range v.queues {
		queue := &v.queues[index]
		if err := v.request(vhostUserSetVringKick, u64Payload(uint64(index)), int(queue.KickRead.Fd())); err != nil {
			return err
		}
		if err := queue.KickRead.Close(); err != nil {
			return err
		}
		queue.KickRead = nil
		if err := v.request(vhostUserSetVringCall, u64Payload(uint64(index)), int(queue.CallWrite.Fd())); err != nil {
			return err
		}
		if err := queue.CallWrite.Close(); err != nil {
			return err
		}
		queue.CallWrite = nil
		if err := syscall.SetNonblock(int(queue.KickWrite.Fd()), true); err != nil {
			return fmt.Errorf("queue %d nonblocking kick: %w", index, err)
		}
		v.callWG.Add(1)
		go v.readCalls(index, queue.CallRead)
	}
	return nil
}

func (v *VhostFS) configureQueue(index int, q *virtq) error {
	state := make([]byte, 8)
	binary.LittleEndian.PutUint32(state[0:4], uint32(index))
	binary.LittleEndian.PutUint32(state[4:8], q.num)
	if err := v.request(vhostUserSetVringNum, state, -1); err != nil {
		return err
	}
	binary.LittleEndian.PutUint32(state[4:8], 0)
	if err := v.request(vhostUserSetVringBase, state, -1); err != nil {
		return err
	}
	addr := make([]byte, 40)
	binary.LittleEndian.PutUint32(addr[0:4], uint32(index))
	binary.LittleEndian.PutUint64(addr[8:16], q.descAddr)
	binary.LittleEndian.PutUint64(addr[16:24], q.usedAddr)
	binary.LittleEndian.PutUint64(addr[24:32], q.availAddr)
	if err := v.request(vhostUserSetVringAddr, addr, -1); err != nil {
		return err
	}
	if !v.configured[index].started {
		binary.LittleEndian.PutUint32(state[4:8], 1)
		if err := v.request(vhostUserSetVringEnable, state, -1); err != nil {
			return err
		}
	}
	v.configured[index] = vhostQueueSnapshot{
		num: q.num, desc: q.descAddr, avail: q.availAddr, used: q.usedAddr,
		configured: true, started: true,
	}
	return nil
}

func (v *VhostFS) readCalls(_ int, file *os.File) {
	defer v.callWG.Done()
	var payload [8]byte
	for {
		if _, err := io.ReadFull(file, payload[:]); err != nil {
			return
		}
		if v.core != nil {
			v.core.RaiseExternalUsedInterrupt()
		}
	}
}

func (v *VhostFS) request(kind uint32, payload []byte, fd int) error {
	var header [12]byte
	binary.LittleEndian.PutUint32(header[0:4], kind)
	binary.LittleEndian.PutUint32(header[4:8], vhostUserVersion|vhostUserNeedReply)
	binary.LittleEndian.PutUint32(header[8:12], uint32(len(payload)))
	if fd >= 0 {
		n, _, err := v.control.WriteMsgUnix(header[:], syscall.UnixRights(fd), nil)
		if err != nil {
			return fmt.Errorf("request %d header/fd: %w", kind, err)
		}
		if n != len(header) {
			return fmt.Errorf("request %d short header %d/%d", kind, n, len(header))
		}
	} else if err := writeAll(v.control, header[:]); err != nil {
		return fmt.Errorf("request %d header: %w", kind, err)
	}
	if err := writeAll(v.control, payload); err != nil {
		return fmt.Errorf("request %d payload: %w", kind, err)
	}
	if _, err := io.ReadFull(v.control, header[:]); err != nil {
		return fmt.Errorf("request %d reply header: %w", kind, err)
	}
	if binary.LittleEndian.Uint32(header[0:4]) != kind || binary.LittleEndian.Uint32(header[4:8])&vhostUserReply == 0 {
		return fmt.Errorf("request %d malformed reply", kind)
	}
	size := binary.LittleEndian.Uint32(header[8:12])
	if size != 8 {
		return fmt.Errorf("request %d reply size %d, want 8", kind, size)
	}
	var ack [8]byte
	if _, err := io.ReadFull(v.control, ack[:]); err != nil {
		return fmt.Errorf("request %d reply: %w", kind, err)
	}
	if value := binary.LittleEndian.Uint64(ack[:]); value != 0 {
		return fmt.Errorf("request %d rejected (%d)", kind, value)
	}
	return nil
}

func (v *VhostFS) Close() error {
	v.closeOnce.Do(func() {
		var errs []error
		for index := range v.queues {
			queue := &v.queues[index]
			// Closing the kick writer releases a backend blocked in read; closing
			// call readers joins our local interrupt goroutines.
			for _, file := range []*os.File{queue.KickWrite, queue.CallRead, queue.KickRead, queue.CallWrite} {
				if file != nil {
					errs = append(errs, file.Close())
				}
			}
			*queue = VhostQueueFiles{}
		}
		if v.control != nil {
			errs = append(errs, v.control.Close())
			v.control = nil
		}
		if v.memory != nil {
			errs = append(errs, v.memory.Close())
			v.memory = nil
		}
		v.callWG.Wait()
		v.closeErr = errors.Join(errs...)
	})
	return v.closeErr
}

func u64Payload(value uint64) []byte {
	payload := make([]byte, 8)
	binary.LittleEndian.PutUint64(payload, value)
	return payload
}

func writeAll(w io.Writer, p []byte) error {
	for len(p) != 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}

var _ Device = (*VhostFS)(nil)
var _ io.Closer = (*VhostFS)(nil)
