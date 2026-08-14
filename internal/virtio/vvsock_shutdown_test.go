//go:build linux || darwin

package virtio

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestVsockShutdownDrainsEarlierRW(t *testing.T) {
	host, device := net.Pipe()
	defer host.Close()

	vs := NewVsock(3, t.TempDir())
	memory := NewRAM(make([]byte, 2<<20), ramBase)
	irqs := &irqRec{raised: map[int]bool{}}
	core := NewCoreAt(vs, memory, MMIOBaseArm64+MMIOStrideArm64, MMIOIRQArm64+1, irqs.line, "vsock-shutdown")
	vs.core = core
	t.Cleanup(func() { _ = vs.Close() })
	setupQueue(memory, core, vsockQueueTx, 8)

	hdr := vsockHdr{
		srcCID: 3, dstCID: vsockHostCID,
		srcPort: 1111, dstPort: 1025,
		typ: vsockTypeStream, bufAlloc: 8192,
	}
	c := &vsockConn{
		key: connKey(hdr.srcPort, hdr.dstPort), nc: device, established: true,
		peerBufAlloc: 8192, outSig: make(chan struct{}, 1), done: make(chan struct{}),
	}
	vs.conns[c.key] = c
	vs.workers.Add(1)
	go func() {
		defer vs.workers.Done()
		vs.pumpOut(c)
	}()

	// Queue RW and SHUTDOWN before one notification. handleTx consumes both
	// while holding core.mu, so pumpOut cannot write until it has seen the
	// shutdown too; this deterministically reproduces the old data-loss race.
	payload := []byte("final output")
	rw := append(hdr.marshal(), payload...)
	rw[30], rw[31] = byte(vsockOpRW), 0
	binary.LittleEndian.PutUint32(rw[24:], uint32(len(payload)))
	shutdown := hdr.marshal()
	shutdown[30], shutdown[31] = byte(vsockOpShutdown), 0

	rwAddr := uint64(ramBase) + uint64(testDataAddr)
	shutdownAddr := rwAddr + 0x100
	if err := memory.writeAt(rwAddr, rw); err != nil {
		t.Fatal(err)
	}
	if err := memory.writeAt(shutdownAddr, shutdown); err != nil {
		t.Fatal(err)
	}
	putDesc(memory, vsockQueueTx, 0, rwAddr, uint32(len(rw)), 0, 0)
	putDesc(memory, vsockQueueTx, 1, shutdownAddr, uint32(len(shutdown)), 0, 0)
	availPush(memory, vsockQueueTx, 0)
	availPush(memory, vsockQueueTx, 1)
	core.MMIOWrite(0x050, vsockQueueTx)

	if err := host.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(host, got); err != nil {
		t.Fatalf("read final payload: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("final payload = %q, want %q", got, payload)
	}
	var extra [1]byte
	if _, err := host.Read(extra[:]); !errors.Is(err, io.EOF) {
		t.Fatalf("read after drained shutdown = %v, want EOF", err)
	}
}
