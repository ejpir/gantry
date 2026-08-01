//go:build linux || darwin

package virtio

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
)

// These tests simulate the guest driver's side of virtio-mmio: they write
// descriptor chains into fake guest RAM and drive the device's MMIO
// registers exactly like the Linux kernel would. This exercises everything
// except the thin KVM exit boundary.

const ramBase = 0x40000000 // matches vmm fdt.go; x86 tests use base 0

const (
	testDescAddr  = 0x10000 // + qn*testStride0
	testAvailAddr = 0x40000 // + qn*testStride0
	testUsedAddr  = 0x70000 // + qn*testStride0
	testDataAddr  = 0x100000
	testStride    = 0x10000
)

type irqRec struct{ raised map[int]bool }

func (r *irqRec) line(irq int, level bool) { r.raised[irq] = level }

// setupQueue wires one virtqueue into fake RAM the way a driver would.
func setupQueue(mem mem, core *Core, qn, num uint32) {
	core.MMIOWrite(0x030, uint32(qn)) // QueueSel
	core.MMIOWrite(0x038, num)        // QueueNum
	core.MMIOWrite(0x080, ramBase+testDescAddr+uint32(qn)*testStride)
	core.MMIOWrite(0x090, ramBase+testAvailAddr+uint32(qn)*testStride)
	core.MMIOWrite(0x0a0, ramBase+testUsedAddr+uint32(qn)*testStride)
	core.MMIOWrite(0x044, 1) // QueueReady
	// zero avail/used headers
	mem.writeAt(ramBase+testAvailAddr+uint64(qn)*testStride, make([]byte, 8))
	mem.writeAt(ramBase+testUsedAddr+uint64(qn)*testStride, make([]byte, 8))
}

func putDesc(mem mem, qn uint32, idx uint16, addr uint64, length uint32, flags uint16, next uint16) {
	var d [16]byte
	binary.LittleEndian.PutUint64(d[0:], addr)
	binary.LittleEndian.PutUint32(d[8:], length)
	binary.LittleEndian.PutUint16(d[12:], flags)
	binary.LittleEndian.PutUint16(d[14:], next)
	mem.writeAt(ramBase+testDescAddr+uint64(qn)*testStride+uint64(idx)*16, d[:])
}

func availPush(mem mem, qn uint32, head uint16) {
	base := ramBase + testAvailAddr + uint64(qn)*testStride
	var idx [2]byte
	mem.readAt(base+2, idx[:])
	n := binary.LittleEndian.Uint16(idx[:])
	var h [2]byte
	binary.LittleEndian.PutUint16(h[:], head)
	mem.writeAt(base+4+uint64(n%8)*2, h[:])
	n++
	binary.LittleEndian.PutUint16(idx[:], n)
	mem.writeAt(base+2, idx[:])
}

type usedElem struct {
	id  uint32
	len uint32
}

func usedIndex(mem mem, qn uint32) uint16 {
	base := ramBase + testUsedAddr + uint64(qn)*testStride
	var idx [2]byte
	mem.readAt(base+2, idx[:])
	return binary.LittleEndian.Uint16(idx[:])
}

func usedAt(mem mem, qn uint32, n uint16) usedElem {
	base := ramBase + testUsedAddr + uint64(qn)*testStride
	var e [8]byte
	mem.readAt(base+4+uint64(n%8)*8, e[:])
	return usedElem{binary.LittleEndian.Uint32(e[0:]), binary.LittleEndian.Uint32(e[4:])}
}

func usedPop(mem mem, qn uint32) (usedElem, bool) {
	n := usedIndex(mem, qn)
	if n == 0 {
		return usedElem{}, false
	}
	return usedAt(mem, qn, n-1), true
}

func TestVirtioBlkRead(t *testing.T) {
	// backing image: 1 MiB, sector i filled with byte i
	img := filepath.Join(t.TempDir(), "rootfs.img")
	data := make([]byte, 1<<20)
	for i := range data {
		data[i] = byte(i / 512)
	}
	if err := os.WriteFile(img, data, 0o644); err != nil {
		t.Fatal(err)
	}
	blk, err := NewBlk(img, false)
	if err != nil {
		t.Fatal(err)
	}
	ram := make([]byte, 2<<20)
	mem := NewRAM(ram, ramBase)
	irqs := &irqRec{raised: map[int]bool{}}
	core := NewCoreAt(blk, mem, MMIOBaseArm64+0*MMIOStrideArm64, MMIOIRQArm64+0, irqs.line, "blk")
	blk.core = core

	if got := core.MMIORead(0x000, 4); got != virtioMagic {
		t.Fatalf("bad magic %#x", got)
	}
	if got := core.MMIORead(0x008, 4); got != 2 {
		t.Fatalf("bad device id %#x", got)
	}
	// features: VERSION_1 must be in high word
	core.MMIOWrite(0x014, 1)
	if f := core.MMIORead(0x010, 4); f&1 == 0 {
		t.Fatal("VERSION_1 not offered")
	}

	setupQueue(mem, core, 0, 8)

	// request: READ sector 2 -> 512 bytes at data addr, status after
	hdr := make([]byte, 16)
	binary.LittleEndian.PutUint32(hdr[0:], BlkTIn)
	binary.LittleEndian.PutUint64(hdr[8:], 2)
	mem.writeAt(ramBase+testDataAddr, hdr)
	putDesc(mem, 0, 0, ramBase+testDataAddr, 16, vringDescFNext, 1)
	putDesc(mem, 0, 1, ramBase+testDataAddr+0x100, 512, vringDescFNext|vringDescFWrite, 2)
	putDesc(mem, 0, 2, ramBase+testDataAddr+0x300, 1, vringDescFWrite, 0)
	availPush(mem, 0, 0)
	core.MMIOWrite(0x050, 0) // QueueNotify

	e, ok := usedPop(mem, 0)
	if !ok {
		t.Fatal("no used element")
	}
	if e.id != 0 || e.len != 513 {
		t.Fatalf("used elem = %+v, want id 0 len 513", e)
	}
	var st [1]byte
	mem.readAt(ramBase+testDataAddr+0x300, st[:])
	if st[0] != BlkSOK {
		t.Fatalf("status = %d", st[0])
	}
	got := make([]byte, 512)
	mem.readAt(ramBase+testDataAddr+0x100, got)
	for i := range got {
		if got[i] != 2 {
			t.Fatalf("data[%d] = %d, want 2", i, got[i])
		}
	}
	if !irqs.raised[MMIOIRQArm64] {
		t.Fatal("IRQ not raised")
	}
	// driver ACKs -> interrupt status register clears (line itself is
	// trigger/pulse semantics; the guest EOI clears the GIC pending state)
	core.MMIOWrite(0x064, 1)
	if core.isr != 0 {
		t.Fatal("isr not cleared after ACK")
	}
}

type testFuseHandler struct {
	t      *testing.T
	called bool
}

func (h *testFuseHandler) HandleRequest(in, out [][]byte) (int, fuse.Status) {
	h.called = true
	if len(in) != 2 || len(in[0]) != 40 || len(in[1]) != 8 {
		h.t.Fatalf("FUSE input IOV shape = %v", []int{len(in[0]), len(in[1])})
	}
	if len(out) != 2 || len(out[0]) != 16 || len(out[1]) != 8 {
		h.t.Fatalf("FUSE output IOV shape = %d/%d", len(out[0]), len(out[1]))
	}
	copy(out[0], []byte("response-header!"))
	copy(out[1], []byte("payload!"))
	return 24, fuse.OK
}

func TestVirtioFSLoopbackProtocol(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "hello.txt"), []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dev, err := NewFS("testshare", root)
	if err != nil {
		t.Fatal(err)
	}
	header := func(op uint32, unique, node uint64, payloadLen int) []byte {
		b := make([]byte, 40)
		binary.LittleEndian.PutUint32(b[0:4], uint32(40+payloadLen))
		binary.LittleEndian.PutUint32(b[4:8], op)
		binary.LittleEndian.PutUint64(b[8:16], unique)
		binary.LittleEndian.PutUint64(b[16:24], node)
		return b
	}

	// FUSE_INIT (opcode 26), protocol 7.38.
	initPayload := make([]byte, 64)
	binary.LittleEndian.PutUint32(initPayload[0:4], 7)
	binary.LittleEndian.PutUint32(initPayload[4:8], 38)
	initOut := [][]byte{make([]byte, 16), make([]byte, 64)}
	n, status := dev.handler.HandleRequest(
		[][]byte{header(26, 1, 0, len(initPayload)), initPayload}, initOut)
	wantInit := 80
	if runtime.GOOS == "darwin" {
		// The vendored go-fuse Darwin protocol advertises minor 19 and
		// therefore returns the legacy 24-byte InitOut.
		wantInit = 40
	}
	if status != fuse.OK || n != wantInit || int32(binary.LittleEndian.Uint32(initOut[0][4:8])) != 0 {
		t.Fatalf("FUSE_INIT: n=%d want=%d status=%v header=%x", n, wantInit, status, initOut[0])
	}
	if major := binary.LittleEndian.Uint32(initOut[1][0:4]); major != 7 {
		t.Fatalf("FUSE_INIT major = %d", major)
	}

	// LOOKUP (opcode 1) proves the protocol dispatcher reaches the actual
	// loopback filesystem and serializes a Linux 128-byte fuse_entry_out.
	name := []byte("hello.txt\x00")
	lookupOut := [][]byte{make([]byte, 16), make([]byte, 128)}
	n, status = dev.handler.HandleRequest(
		[][]byte{header(1, 2, 1, len(name)), name}, lookupOut)
	if status != fuse.OK || n != 144 || int32(binary.LittleEndian.Uint32(lookupOut[0][4:8])) != 0 {
		t.Fatalf("FUSE_LOOKUP: n=%d status=%v header=%x", n, status, lookupOut[0])
	}
	if node := binary.LittleEndian.Uint64(lookupOut[1][0:8]); node < 2 {
		t.Fatalf("FUSE_LOOKUP node ID = %d", node)
	}
}

func TestVirtioBlkWrite(t *testing.T) {
	img := filepath.Join(t.TempDir(), "rwlayer.img")
	if err := os.WriteFile(img, make([]byte, 1<<20), 0o644); err != nil {
		t.Fatal(err)
	}
	blk, err := NewBlk(img, true)
	if err != nil {
		t.Fatal(err)
	}
	defer blk.file.Close()
	if f := blk.features(); f&(1<<BlkFRO) != 0 || f&(1<<BlkFFlush) == 0 {
		t.Fatalf("writable features = %#x (want FLUSH, no RO)", f)
	}
	ram := make([]byte, 2<<20)
	mem := NewRAM(ram, ramBase)
	irqs := &irqRec{raised: map[int]bool{}}
	core := NewCoreAt(blk, mem, MMIOBaseArm64+0*MMIOStrideArm64, MMIOIRQArm64+0, irqs.line, "blk")
	blk.core = core
	setupQueue(mem, core, 0, 8)

	// WRITE sector 4: header + 512 data bytes (readable), status (writable)
	hdr := make([]byte, 16)
	binary.LittleEndian.PutUint32(hdr[0:], BlkTOut)
	binary.LittleEndian.PutUint64(hdr[8:], 4)
	mem.writeAt(ramBase+testDataAddr, hdr)
	payload := make([]byte, 512)
	for i := range payload {
		payload[i] = 0xab
	}
	mem.writeAt(ramBase+testDataAddr+0x100, payload)
	putDesc(mem, 0, 0, ramBase+testDataAddr, 16, vringDescFNext, 1)
	putDesc(mem, 0, 1, ramBase+testDataAddr+0x100, 512, vringDescFNext, 2)
	putDesc(mem, 0, 2, ramBase+testDataAddr+0x300, 1, vringDescFWrite, 0)
	availPush(mem, 0, 0)
	core.MMIOWrite(0x050, 0)

	e, ok := usedPop(mem, 0)
	if !ok || e.len != 1 {
		t.Fatalf("used elem = %+v ok=%v, want len 1 (status only)", e, ok)
	}
	var st [1]byte
	mem.readAt(ramBase+testDataAddr+0x300, st[:])
	if st[0] != BlkSOK {
		t.Fatalf("write status = %d", st[0])
	}
	got := make([]byte, 512)
	if _, err := blk.file.ReadAt(got, 4*512); err != nil {
		t.Fatal(err)
	}
	if got[0] != 0xab || got[511] != 0xab {
		t.Fatal("image content not updated")
	}

	// FLUSH succeeds on a writable device.
	binary.LittleEndian.PutUint32(hdr[0:], BlkTFlush)
	mem.writeAt(ramBase+testDataAddr, hdr)
	putDesc(mem, 0, 0, ramBase+testDataAddr, 16, vringDescFNext, 2)
	availPush(mem, 0, 0)
	core.MMIOWrite(0x050, 0)
	if e, ok := usedPop(mem, 0); !ok || e.id != 0 {
		t.Fatalf("flush used elem = %+v ok=%v", e, ok)
	}
	mem.readAt(ramBase+testDataAddr+0x300, st[:])
	if st[0] != BlkSOK {
		t.Fatalf("flush status = %d", st[0])
	}

	// A read-only device still rejects writes.
	roBlk, err := NewBlk(img, false)
	if err != nil {
		t.Fatal(err)
	}
	defer roBlk.file.Close()
	if roBlk.features()&(1<<BlkFRO) == 0 {
		t.Fatal("read-only device lost VIRTIO_BLK_F_RO")
	}
}

func TestVirtioRNG(t *testing.T) {
	dev := NewRNG()
	ram := make([]byte, 2<<20)
	mem := NewRAM(ram, ramBase)
	irqs := &irqRec{raised: map[int]bool{}}
	core := NewCoreAt(dev, mem, MMIOBaseArm64+0*MMIOStrideArm64, MMIOIRQArm64+0, irqs.line, "rng")
	dev.core = core
	setupQueue(mem, core, 0, 8)

	// driver posts a 64-byte writable buffer; device fills it
	putDesc(mem, 0, 0, ramBase+testDataAddr, 64, vringDescFWrite, 0)
	availPush(mem, 0, 0)
	core.MMIOWrite(0x050, 0)
	e, ok := usedPop(mem, 0)
	if !ok || e.len != 64 {
		t.Fatalf("used elem = %+v ok=%v, want len 64", e, ok)
	}
	out := make([]byte, 64)
	mem.readAt(ramBase+testDataAddr, out)
	var nonzero int
	for _, b := range out {
		if b != 0 {
			nonzero++
		}
	}
	if nonzero < 32 { // comically conservative randomness check
		t.Fatalf("rng output looks non-random (%d/64 nonzero)", nonzero)
	}
}

func TestVirtioRTC(t *testing.T) {
	dev := NewRTC()
	dev.now = func() time.Time { return time.Unix(1_700_000_000, 123_456_789) }
	if dev.deviceID() != 17 || dev.numQueues() != 1 {
		t.Fatalf("id=%d queues=%d", dev.deviceID(), dev.numQueues())
	}
	ram := make([]byte, 2<<20)
	mem := NewRAM(ram, ramBase)
	irqs := &irqRec{raised: map[int]bool{}}
	core := NewCoreAt(dev, mem, MMIOBaseArm64+0*MMIOStrideArm64, MMIOIRQArm64+0, irqs.line, "rtc")
	dev.core = core
	setupQueue(mem, core, 0, 8)

	roundTrip := func(req []byte) (status byte, body []byte) {
		mem.writeAt(ramBase+testDataAddr, req)
		putDesc(mem, 0, 0, ramBase+testDataAddr, uint32(len(req)), vringDescFNext, 1)
		putDesc(mem, 0, 1, ramBase+testDataAddr+0x100, RTCRespLen, vringDescFWrite, 0)
		availPush(mem, 0, 0)
		core.MMIOWrite(0x050, 0)
		e, ok := usedPop(mem, 0)
		if !ok || e.len != RTCRespLen {
			t.Fatalf("used elem = %+v ok=%v", e, ok)
		}
		out := make([]byte, RTCRespLen)
		mem.readAt(ramBase+testDataAddr+0x100, out)
		return out[0], out[8:]
	}

	// CFG -> one clock
	st, body := roundTrip([]byte{0x00, 0x10, 0, 0, 0, 0, 0, 0})
	if st != RTCSOK || binary.LittleEndian.Uint16(body) != 1 {
		t.Fatalf("CFG: status=%d num_clocks=%d", st, binary.LittleEndian.Uint16(body))
	}
	// CLOCK_CAP clock 0 -> UTC
	st, body = roundTrip([]byte{0x01, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	if st != RTCSOK || body[0] != 0 {
		t.Fatalf("CLOCK_CAP: status=%d type=%d", st, body[0])
	}
	// READ clock 0 -> host time in ns
	st, body = roundTrip([]byte{0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	want := uint64(1_700_000_000)*1e9 + 123_456_789
	if st != RTCSOK || binary.LittleEndian.Uint64(body) != want {
		t.Fatalf("READ: status=%d reading=%d want %d", st, binary.LittleEndian.Uint64(body), want)
	}
	// READ clock 1 -> ENODEV
	st, _ = roundTrip([]byte{0x01, 0x00, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0})
	if st != RTCSENODEV {
		t.Fatalf("READ clock 1: status=%d", st)
	}
	// alarm request without the feature -> EOPNOTSUPP
	st, _ = roundTrip([]byte{0x04, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	if st != RTCSEOPNOTSUPP {
		t.Fatalf("alarm: status=%d", st)
	}
}

func TestMMIONoSharedMemoryRegion(t *testing.T) {
	// The guest kernel distinguishes "no SHM region" (length ~0) from a
	// present zero-length window (length 0). virtio-fs probe fails with
	// EBUSY if we report the latter (observed with the nerdbox kernel).
	core := &Core{}
	if got := core.MMIORead(0xb0, 4); got != 0xffffffff {
		t.Fatalf("SHMLenLow = %#x, want 0xffffffff", got)
	}
	if got := core.MMIORead(0xb4, 4); got != 0xffffffff {
		t.Fatalf("SHMLenHigh = %#x, want 0xffffffff", got)
	}
	if got := core.MMIORead(0xb8, 4); got != 0 {
		t.Fatalf("SHMBaseLow = %#x, want 0", got)
	}
}

func TestVirtioFSTransport(t *testing.T) {
	handler := &testFuseHandler{t: t}
	dev := &FS{tag: "hostshare", handler: handler}
	ram := make([]byte, 2<<20)
	mem := NewRAM(ram, ramBase)
	irqs := &irqRec{raised: map[int]bool{}}
	core := NewCoreAt(dev, mem, MMIOBaseArm64+0*MMIOStrideArm64, MMIOIRQArm64+0, irqs.line, "fs")
	dev.core = core

	if got := core.MMIORead(0x008, 4); got != virtioFSDeviceID {
		t.Fatalf("device id = %d", got)
	}
	var cfg [40]byte
	for i := 0; i < len(cfg); i += 4 {
		v := core.MMIORead(0x100+uint64(i), 4)
		binary.LittleEndian.PutUint32(cfg[i:], v)
	}
	if string(cfg[:9]) != "hostshare" || binary.LittleEndian.Uint32(cfg[36:]) != 1 {
		t.Fatalf("bad virtio-fs config: %q queues=%d", cfg[:36], binary.LittleEndian.Uint32(cfg[36:]))
	}

	setupQueue(mem, core, virtioFSRequestQ, 8)
	base := uint64(ramBase + testDataAddr)
	mem.writeAt(base, make([]byte, 48))
	putDesc(mem, virtioFSRequestQ, 0, base, 40, vringDescFNext, 1)
	putDesc(mem, virtioFSRequestQ, 1, base+0x100, 8, vringDescFNext, 2)
	putDesc(mem, virtioFSRequestQ, 2, base+0x200, 16, vringDescFNext|vringDescFWrite, 3)
	putDesc(mem, virtioFSRequestQ, 3, base+0x300, 8, vringDescFWrite, 0)
	availPush(mem, virtioFSRequestQ, 0)
	core.MMIOWrite(0x050, virtioFSRequestQ)

	if !handler.called {
		t.Fatal("FUSE protocol handler not called")
	}
	if e, ok := usedPop(mem, virtioFSRequestQ); !ok || e.id != 0 || e.len != 24 {
		t.Fatalf("bad FUSE used elem: %+v ok=%v", e, ok)
	}
	got := make([]byte, 16)
	mem.readAt(base+0x200, got)
	if string(got) != "response-header!" {
		t.Fatalf("response header = %q", got)
	}
	got = make([]byte, 8)
	mem.readAt(base+0x300, got)
	if string(got) != "payload!" {
		t.Fatalf("response payload = %q", got)
	}
	if !irqs.raised[MMIOIRQArm64] {
		t.Fatal("virtio-fs IRQ not raised")
	}
}

type testPacketConn struct {
	rx chan []byte
	tx chan []byte
}

func (c *testPacketConn) Read(p []byte) (int, error) {
	frame := <-c.rx
	return copy(p, frame), nil
}
func (c *testPacketConn) Write(p []byte) (int, error) {
	c.tx <- append([]byte(nil), p...)
	return len(p), nil
}
func (c *testPacketConn) Close() error { return nil }

func shortSocketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "gantry-sock-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func TestVirtioNetUnixgramVFKIT(t *testing.T) {
	path := filepath.Join(shortSocketDir(t), "net.sock")
	addr, err := net.ResolveUnixAddr("unixgram", path)
	if err != nil {
		t.Fatal(err)
	}
	server, err := net.ListenUnixgram("unixgram", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	nic, err := NewNetUnixgram(path, [6]byte{2, 0, 0, 0, 0, 1}, true)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		nic.conn.Close()
		os.Remove(nic.localPath)
	}()
	server.SetReadDeadline(time.Now().Add(15 * time.Second))
	buf := make([]byte, 16)
	n, _, err := server.ReadFromUnix(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "VFKT" {
		t.Fatalf("handshake = %q", buf[:n])
	}
}

func TestVirtioNetTxRx(t *testing.T) {
	backend := &testPacketConn{rx: make(chan []byte, 1), tx: make(chan []byte, 1)}
	mac := [6]byte{0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee}
	nic := &Net{mac: mac, conn: backend}
	ram := make([]byte, 2<<20)
	mem := NewRAM(ram, ramBase)
	irqs := &irqRec{raised: map[int]bool{}}
	core := NewCoreAt(nic, mem, MMIOBaseArm64+0*MMIOStrideArm64, MMIOIRQArm64+0, irqs.line, "net")
	nic.core = core

	if got := core.MMIORead(0x008, 4); got != virtioNetDeviceID {
		t.Fatalf("device id = %d", got)
	}
	if got := core.MMIORead(0x100, 4); got != 0xe4ef945a {
		t.Fatalf("first MAC bytes = %#x", got)
	}
	if got := core.MMIORead(0x104, 2); got != 0xee0c {
		t.Fatalf("last MAC bytes = %#x", got)
	}
	core.MMIOWrite(0x014, 0)
	if got := core.MMIORead(0x010, 4); got&(1<<virtioNetFMac) == 0 {
		t.Fatal("VIRTIO_NET_F_MAC not offered")
	}

	setupQueue(mem, core, virtioNetRxQ, 8)
	setupQueue(mem, core, virtioNetTxQ, 8)
	nic.start()

	// Guest TX contains virtio_net_hdr_v1 followed by one Ethernet frame.
	txFrame := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee, 0x08, 0x06, 1, 2, 3, 4}
	txPacket := append(make([]byte, virtioNetHdrLen), txFrame...)
	mem.writeAt(ramBase+testDataAddr, txPacket)
	putDesc(mem, virtioNetTxQ, 0, ramBase+testDataAddr, uint32(len(txPacket)), 0, 0)
	availPush(mem, virtioNetTxQ, 0)
	core.MMIOWrite(0x050, virtioNetTxQ)
	select {
	case got := <-backend.tx:
		if string(got) != string(txFrame) {
			t.Fatalf("backend TX = %x, want %x", got, txFrame)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("timeout waiting for net TX")
	}
	if e, ok := usedPop(mem, virtioNetTxQ); !ok || e.id != 0 || e.len != 0 {
		t.Fatalf("bad TX used elem: %+v ok=%v", e, ok)
	}

	// Host RX gets a zeroed virtio header prepended and is scattered into the
	// writable descriptor posted by the guest.
	rxAddr := uint64(ramBase + testDataAddr + 0x1000)
	putDesc(mem, virtioNetRxQ, 0, rxAddr, 2048, vringDescFWrite, 0)
	availPush(mem, virtioNetRxQ, 0)
	core.MMIOWrite(0x050, virtioNetRxQ)
	rxFrame := []byte{0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee, 0x52, 0x55, 0x0a, 0x00, 0x02, 0x02, 0x08, 0x00, 5, 6, 7, 8}
	backend.rx <- rxFrame
	deadline := time.Now().Add(15 * time.Second)
	got := make([]byte, virtioNetHdrLen+len(rxFrame))
	for {
		// readLoop delivers RX frames from its own goroutine under core.mu
		core.mu.Lock()
		e, ok := usedPop(mem, virtioNetRxQ)
		if ok {
			mem.readAt(rxAddr, got)
		}
		core.mu.Unlock()
		if ok {
			if e.id != 0 || e.len != uint32(len(got)) {
				t.Fatalf("bad RX used elem: %+v", e)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("timeout waiting for net RX")
		}
		time.Sleep(time.Millisecond)
	}
	if string(got[virtioNetHdrLen:]) != string(rxFrame) {
		t.Fatalf("guest RX = %x, want %x", got[virtioNetHdrLen:], rxFrame)
	}
	for i, b := range got[:virtioNetHdrLen] {
		if b != 0 {
			t.Fatalf("virtio net header byte %d = %#x", i, b)
		}
	}
	if !irqs.raised[MMIOIRQArm64] {
		t.Fatal("net IRQ not raised")
	}
}

func TestVirtioVsockHandshakeAndRW(t *testing.T) {
	hostSide, guestSide := net.Pipe()
	defer hostSide.Close()
	// net.Pipe is synchronous; the host side needs a concurrent reader,
	// like a real buffered unix socket would provide.
	hostRx := make(chan []byte, 16)
	go func() {
		for {
			buf := make([]byte, 4096)
			n, err := hostSide.Read(buf)
			if n > 0 {
				hostRx <- buf[:n]
			}
			if err != nil {
				return
			}
		}
	}()

	vs := NewVsock(3, t.TempDir())
	vs.dial = func(port uint32) (net.Conn, error) {
		if port != 1025 {
			t.Fatalf("unexpected dial port %d", port)
		}
		return guestSide, nil
	}
	ram := make([]byte, 2<<20)
	mem := NewRAM(ram, ramBase)
	irqs := &irqRec{raised: map[int]bool{}}
	core := NewCoreAt(vs, mem, MMIOBaseArm64+1*MMIOStrideArm64, MMIOIRQArm64+1, irqs.line, "vsock")
	vs.core = core
	vs.verboseLog = true

	setupQueue(mem, core, vsockQueueRx, 8)
	setupQueue(mem, core, vsockQueueTx, 8)

	postRxBuf := func(head uint16) {
		putDesc(mem, 0, head, ramBase+testDataAddr+uint64(head)*0x100, vsockHdrLen, vringDescFNext|vringDescFWrite, head+1)
		putDesc(mem, 0, head+1, ramBase+testDataAddr+0x800+uint64(head)*0x100, 1024, vringDescFWrite, 0)
		availPush(mem, 0, head)
		core.MMIOWrite(0x050, vsockQueueRx)
	}

	// guest sends REQUEST cid 3:1111 -> 2:1025
	hdr := vsockHdr{srcCID: 3, dstCID: 2, srcPort: 1111, dstPort: 1025,
		typ: vsockTypeStream, op: vsockOpRequest, bufAlloc: 8192}
	mem.writeAt(ramBase+testDataAddr, hdr.marshal())
	putDesc(mem, 1, 0, ramBase+testDataAddr, vsockHdrLen, 0, 0)
	availPush(mem, 1, 0)
	postRxBuf(0) // rx buffer for the RESPONSE
	core.MMIOWrite(0x050, vsockQueueTx)

	e, ok := usedPop(mem, vsockQueueRx)
	if !ok {
		t.Fatal("no RESPONSE in rx used ring")
	}
	respBuf := make([]byte, vsockHdrLen)
	mem.readAt(ramBase+testDataAddr, respBuf)
	resp := parseVsockHdr(respBuf)
	if resp.op != vsockOpResponse || resp.srcCID != 2 || resp.dstCID != 3 || resp.srcPort != 1025 || resp.dstPort != 1111 {
		t.Fatalf("bad RESPONSE: %+v", resp)
	}
	_ = e

	// guest -> host RW "hello"
	msg := append(hdr.marshal(), []byte("hello")...)
	binary.LittleEndian.PutUint32(msg[24:], 5)
	msg[30], msg[31] = byte(vsockOpRW), 0
	mem.writeAt(ramBase+testDataAddr, msg)
	putDesc(mem, 1, 1, ramBase+testDataAddr, uint32(len(msg)), 0, 0)
	availPush(mem, 1, 1)
	core.MMIOWrite(0x050, vsockQueueTx)

	var got []byte
	select {
	case got = <-hostRx:
	case <-time.After(15 * time.Second):
		t.Fatal("timeout waiting for guest->host RW")
	}
	if string(got) != "hello" {
		t.Fatalf("host read: %q", got)
	}

	// host -> guest RW "world"
	// (credit updates — from the guest's "hello" RW and from pumpOut's
	// post-write accounting — legitimately consume rx buffers first, and
	// their number/timing is async, so post plenty and pick the used elem
	// that actually carries a payload rather than a fixed head id)
	postRxBuf(2)
	postRxBuf(4)
	postRxBuf(6)
	seenUsed := usedIndex(mem, vsockQueueRx)
	if _, err := hostSide.Write([]byte("world")); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(15 * time.Second)
	payload := make([]byte, 5)
	hdrBuf := make([]byte, vsockHdrLen)
	for {
		found := false
		// pumpHost delivers host->guest data from its own goroutine (core.mu).
		// Credit updates can be delivered after the data packet, so scan all
		// new used elements instead of looking only at the latest one.
		core.mu.Lock()
		currentUsed := usedIndex(mem, vsockQueueRx)
		for n := seenUsed; n != currentUsed; n++ {
			e := usedAt(mem, vsockQueueRx, n)
			if e.len > vsockHdrLen {
				mem.readAt(ramBase+testDataAddr+0x800+uint64(e.id)*0x100, payload)
				mem.readAt(ramBase+testDataAddr+uint64(e.id)*0x100, hdrBuf)
				found = true
				break
			}
		}
		seenUsed = currentUsed
		core.mu.Unlock()
		if found {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("timeout waiting for host->guest RW")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if string(payload) != "world" {
		t.Fatalf("guest got %q", payload)
	}
	// header of that packet must be an RW op addressed to the guest
	rw := parseVsockHdr(hdrBuf)
	if rw.op != vsockOpRW || rw.dstCID != 3 || rw.dstPort != 1111 {
		t.Fatalf("bad RW header: %+v", rw)
	}
	if !irqs.raised[MMIOIRQArm64+1] {
		t.Fatal("vsock IRQ not raised")
	}
}

func TestVirtioVsockHostListen(t *testing.T) {
	dir := shortSocketDir(t)
	vs := NewVsock(3, dir)
	ram := make([]byte, 2<<20)
	mem := NewRAM(ram, ramBase)
	irqs := &irqRec{raised: map[int]bool{}}
	core := NewCoreAt(vs, mem, MMIOBaseArm64+1*MMIOStrideArm64, MMIOIRQArm64+1, irqs.line, "vsock")
	vs.core = core

	setupQueue(mem, core, vsockQueueRx, 8)
	setupQueue(mem, core, vsockQueueTx, 8)

	path, err := vs.AddListen(1026)
	if err != nil {
		t.Fatal(err)
	}
	// guest posts an rx buffer so the REQUEST can be delivered
	postRx := func(head uint16) {
		putDesc(mem, 0, head, ramBase+testDataAddr+uint64(head)*0x100, vsockHdrLen, vringDescFNext|vringDescFWrite, head+1)
		putDesc(mem, 0, head+1, ramBase+testDataAddr+0x800+uint64(head)*0x100, 1024, vringDescFWrite, 0)
		availPush(mem, 0, head)
		core.MMIOWrite(0x050, vsockQueueRx)
	}
	postRx(0)

	// host client connects -> device must emit a REQUEST into the guest rx ring
	hc, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer hc.Close()

	deadline := time.Now().Add(15 * time.Second)
	var e usedElem
	var req vsockHdr
	for {
		// the device writes the used ring and rx buffer from its own
		// goroutine (under core.mu); take the same lock when peeking.
		core.mu.Lock()
		var ok bool
		var hdrBuf []byte
		e, ok = usedPop(mem, vsockQueueRx)
		if ok {
			hdrBuf = make([]byte, vsockHdrLen)
			mem.readAt(ramBase+testDataAddr, hdrBuf)
		}
		core.mu.Unlock()
		if ok {
			req = parseVsockHdr(hdrBuf)
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("timeout waiting for host-originated REQUEST")
		}
		time.Sleep(5 * time.Millisecond)
	}
	_ = e
	if req.op != vsockOpRequest || req.srcCID != 2 || req.dstCID != 3 || req.dstPort != 1026 {
		t.Fatalf("bad host-originated REQUEST: %+v", req)
	}

	// guest accepts: RESPONSE on tx queue
	resp := vsockHdr{srcCID: 3, dstCID: 2, srcPort: 1026, dstPort: req.srcPort,
		typ: vsockTypeStream, op: vsockOpResponse, bufAlloc: 8192}
	mem.writeAt(ramBase+testDataAddr, resp.marshal())
	putDesc(mem, 1, 0, ramBase+testDataAddr, vsockHdrLen, 0, 0)
	availPush(mem, 1, 0)
	core.MMIOWrite(0x050, vsockQueueTx)

	key := connKey(1026, req.srcPort)
	if c := vs.conns[key]; c == nil || !c.established {
		t.Fatal("conn not established after RESPONSE")
	}

	// guest -> host RW after establishment
	msg := append(resp.marshal(), []byte("ping")...)
	binary.LittleEndian.PutUint32(msg[24:], 4)
	msg[30], msg[31] = byte(vsockOpRW), 0
	mem.writeAt(ramBase+testDataAddr, msg)
	putDesc(mem, 1, 1, ramBase+testDataAddr, uint32(len(msg)), 0, 0)
	availPush(mem, 1, 1)
	core.MMIOWrite(0x050, vsockQueueTx)

	hc.SetReadDeadline(time.Now().Add(15 * time.Second))
	got := make([]byte, 4)
	if _, err := io_ReadFull(hc, got); err != nil || string(got) != "ping" {
		t.Fatalf("host client read: %q %v", got, err)
	}
}

func io_ReadFull(c net.Conn, buf []byte) (int, error) {
	n := 0
	for n < len(buf) {
		m, err := c.Read(buf[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}
