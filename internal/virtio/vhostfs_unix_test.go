//go:build linux || darwin

package virtio

import (
	"bytes"
	"encoding/binary"
	"net"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/hanwen/go-fuse/v2/virtiofs"
)

func testUnixConnPair(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	makeConn := func(fd int, name string) *net.UnixConn {
		file := os.NewFile(uintptr(fd), name)
		conn, err := net.FileConn(file)
		_ = file.Close()
		if err != nil {
			t.Fatal(err)
		}
		unixConn, ok := conn.(*net.UnixConn)
		if !ok {
			t.Fatalf("socketpair conn = %T", conn)
		}
		return unixConn
	}
	return makeConn(fds[0], "vhost-test-frontend"), makeConn(fds[1], "vhost-test-backend")
}

func testVhostQueues(t *testing.T) []VhostQueueFiles {
	t.Helper()
	queues := make([]VhostQueueFiles, virtioFSQueueCount)
	for index := range queues {
		kickRead, kickWrite, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		callRead, callWrite, err := os.Pipe()
		if err != nil {
			_ = kickRead.Close()
			_ = kickWrite.Close()
			t.Fatal(err)
		}
		queues[index] = VhostQueueFiles{
			KickRead: kickRead, KickWrite: kickWrite,
			CallRead: callRead, CallWrite: callWrite,
		}
	}
	return queues
}

func TestVhostFSCompletesEachBatchedHeadOnce(t *testing.T) {
	previousProcs := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(previousProcs)
	const (
		ramSize   = 2 << 20
		batchSize = 64
		queueSize = 128
	)
	file, err := os.CreateTemp(t.TempDir(), "vhost-batch-ram-*")
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(ramSize); err != nil {
		t.Fatal(err)
	}
	ram, err := syscall.Mmap(int(file.Fd()), 0, ramSize,
		syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = syscall.Munmap(ram) }()
	mem := NewRAM(ram, ramBase)
	frontend, backend := testUnixConnPair(t)
	endpoint, err := NewVhostEndpoint(frontend, testVhostQueues(t))
	if err != nil {
		t.Fatal(err)
	}
	device, err := endpoint.NewDevice("vhost-batch", file, ramBase, ramSize)
	if err != nil {
		t.Fatal(err)
	}
	core := NewCoreAt(device, mem, MMIOBaseArm64, MMIOIRQArm64, func(int, bool) {}, "vhost-batch")
	defer func() { _ = core.Close() }()

	var started atomic.Int32
	var once sync.Once
	allStarted := make(chan struct{})
	release := make(chan struct{})
	var handledMu sync.Mutex
	handled := make([]int, batchSize)
	var handlers sync.WaitGroup
	handlers.Add(batchSize)
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- virtiofs.ServeConn(backend, func(read, write [][]byte) int {
			defer handlers.Done()
			if len(read) != 1 || len(read[0]) != 40 || len(write) != 1 || len(write[0]) != 16 {
				return 0
			}
			if started.Add(1) == batchSize {
				once.Do(func() { close(allStarted) })
			}
			<-release
			id := int(read[0][0])
			if id < batchSize {
				handledMu.Lock()
				handled[id]++
				handledMu.Unlock()
				write[0][0] = byte(id + 1)
			}
			return 1
		}, false, func(func([]byte) fuse.Status) {})
	}()

	setupQueue(mem, core, virtioFSRequestQ, queueSize)
	core.MMIOWrite(0x020, uint32(vhostRingIndirectDesc|vhostRingEventIdx))
	availBase := uint64(ramBase + testAvailAddr + virtioFSRequestQ*testStride)
	for id := uint16(0); id < batchSize; id++ {
		tableAddress := uint64(ramBase + testDataAddr + uint64(id)*0x40)
		requestAddress := uint64(ramBase + testDataAddr + 0x10000 + uint64(id)*0x40)
		responseAddress := uint64(ramBase + testDataAddr + 0x20000 + uint64(id)*0x40)
		var table [32]byte
		binary.LittleEndian.PutUint64(table[0:8], requestAddress)
		binary.LittleEndian.PutUint32(table[8:12], 40)
		binary.LittleEndian.PutUint16(table[12:14], vringDescFNext)
		binary.LittleEndian.PutUint16(table[14:16], 1)
		binary.LittleEndian.PutUint64(table[16:24], responseAddress)
		binary.LittleEndian.PutUint32(table[24:28], 16)
		binary.LittleEndian.PutUint16(table[28:30], vringDescFWrite)
		if err := mem.writeAt(tableAddress, table[:]); err != nil {
			t.Fatal(err)
		}
		request := make([]byte, 40)
		request[0] = byte(id)
		if err := mem.writeAt(requestAddress, request); err != nil {
			t.Fatal(err)
		}
		putDesc(mem, virtioFSRequestQ, id, tableAddress, uint32(len(table)), vringDescFIndirect, 0)
		var head [2]byte
		binary.LittleEndian.PutUint16(head[:], id)
		if err := mem.writeAt(availBase+4+uint64(id)*2, head[:]); err != nil {
			t.Fatal(err)
		}
	}
	var availIndex [2]byte
	binary.LittleEndian.PutUint16(availIndex[:], batchSize)
	if err := mem.writeAt(availBase+2, availIndex[:]); err != nil {
		t.Fatal(err)
	}
	core.MMIOWrite(0x050, virtioFSRequestQ)
	select {
	case <-allStarted:
	case <-time.After(5 * time.Second):
		t.Fatalf("only %d/%d batched requests reached the handler", started.Load(), batchSize)
	}
	close(release)

	deadline := time.Now().Add(5 * time.Second)
	for usedIndex(mem, virtioFSRequestQ) != batchSize && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := usedIndex(mem, virtioFSRequestQ); got != batchSize {
		t.Fatalf("used index = %d, want %d", got, batchSize)
	}
	handlers.Wait()
	seenHeads := make([]int, batchSize)
	usedBase := uint64(ramBase + testUsedAddr + virtioFSRequestQ*testStride)
	for index := 0; index < batchSize; index++ {
		var used [8]byte
		if err := mem.readAt(usedBase+4+uint64(index)*8, used[:]); err != nil {
			t.Fatal(err)
		}
		head := int(binary.LittleEndian.Uint32(used[0:4]))
		if head < 0 || head >= batchSize {
			t.Fatalf("used[%d] head = %d", index, head)
		}
		seenHeads[head]++
	}
	for id := 0; id < batchSize; id++ {
		if seenHeads[id] != 1 || handled[id] != 1 {
			t.Fatalf("head %d: used=%d handled=%d, want one each", id, seenHeads[id], handled[id])
		}
		var response [1]byte
		responseAddress := uint64(ramBase + testDataAddr + 0x20000 + uint64(id)*0x40)
		if err := mem.readAt(responseAddress, response[:]); err != nil {
			t.Fatal(err)
		}
		if response[0] != byte(id+1) {
			t.Fatalf("head %d response = %d", id, response[0])
		}
	}
	if err := core.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-serverErr:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("vhost backend did not stop")
	}
}

func TestVhostFSProcessesQueueInSharedRAM(t *testing.T) {
	const ramSize = 2 << 20
	file, err := os.CreateTemp(t.TempDir(), "vhost-ram-*")
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(ramSize); err != nil {
		t.Fatal(err)
	}
	ram, err := syscall.Mmap(int(file.Fd()), 0, ramSize,
		syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = syscall.Munmap(ram) }()

	frontend, backend := testUnixConnPair(t)
	queues := testVhostQueues(t)
	endpoint, err := NewVhostEndpoint(frontend, queues)
	if err != nil {
		t.Fatal(err)
	}
	device, err := endpoint.NewDevice("vhost-test", file, ramBase, ramSize)
	if err != nil {
		t.Fatal(err)
	}
	irq := make(chan struct{}, 1)
	core := NewCoreAt(device, NewRAM(ram, ramBase), MMIOBaseArm64, MMIOIRQArm64,
		func(_ int, level bool) {
			if level {
				select {
				case irq <- struct{}{}:
				default:
				}
			}
		}, "vhost-test")
	defer func() { _ = core.Close() }()

	request := bytes.Repeat([]byte{0xa5}, 40)
	response := bytes.Repeat([]byte{0x5a}, 16)
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- virtiofs.ServeConn(backend, func(read, write [][]byte) int {
			if len(read) != 1 || !bytes.Equal(read[0], request) {
				return 0
			}
			copy(write[0], response)
			return len(response)
		}, false, func(func([]byte) fuse.Status) {})
	}()

	setupQueue(NewRAM(ram, ramBase), core, virtioFSRequestQ, 8)
	if features := core.MMIORead(0x010, 4); features&uint32(vhostRingEventIdx) == 0 {
		t.Fatalf("frontend does not advertise EVENT_IDX: %#x", features)
	}
	core.MMIOWrite(0x020, uint32(vhostRingIndirectDesc|vhostRingEventIdx))
	putDesc(NewRAM(ram, ramBase), virtioFSRequestQ, 0, ramBase+testDataAddr, uint32(len(request)), vringDescFNext, 1)
	putDesc(NewRAM(ram, ramBase), virtioFSRequestQ, 1, ramBase+testDataAddr+128, uint32(len(response)), vringDescFWrite, 0)
	copy(ram[testDataAddr:], request)
	availPush(NewRAM(ram, ramBase), virtioFSRequestQ, 0)
	core.MMIOWrite(0x050, virtioFSRequestQ)

	select {
	case <-irq:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for vhost completion interrupt")
	}
	if got := ram[testDataAddr+128 : testDataAddr+128+uint64(len(response))]; !bytes.Equal(got, response) {
		t.Fatalf("response = %x, want %x", got, response)
	}
	if status := core.MMIORead(0x060, 4); status&virtioIntUsedBuffer == 0 {
		t.Fatalf("interrupt status = %#x", status)
	}
	core.MMIOWrite(0x064, virtioIntUsedBuffer)

	// Rearm EVENT_IDX at the consumed index before submitting another request.
	setAvailUsedEvent(NewRAM(ram, ramBase), virtioFSRequestQ, 8, 1)
	putDesc(NewRAM(ram, ramBase), virtioFSRequestQ, 2, ramBase+testDataAddr+256, uint32(len(request)), vringDescFNext, 3)
	putDesc(NewRAM(ram, ramBase), virtioFSRequestQ, 3, ramBase+testDataAddr+384, uint32(len(response)), vringDescFWrite, 0)
	copy(ram[testDataAddr+256:], request)
	availPush(NewRAM(ram, ramBase), virtioFSRequestQ, 2)
	core.MMIOWrite(0x050, virtioFSRequestQ)
	select {
	case <-irq:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for second EVENT_IDX interrupt")
	}
	if got := ram[testDataAddr+384 : testDataAddr+384+uint64(len(response))]; !bytes.Equal(got, response) {
		t.Fatalf("second response = %x, want %x", got, response)
	}
	core.MMIOWrite(0x064, virtioIntUsedBuffer)
	for {
		select {
		case <-irq:
			continue
		default:
		}
		break
	}

	// An event index beyond the next completion suppresses the call doorbell,
	// but the used ring must still advance. Rearming at that index makes the
	// following completion notify again.
	setAvailUsedEvent(NewRAM(ram, ramBase), virtioFSRequestQ, 8, 4)
	putDesc(NewRAM(ram, ramBase), virtioFSRequestQ, 4, ramBase+testDataAddr+512, uint32(len(request)), vringDescFNext, 5)
	putDesc(NewRAM(ram, ramBase), virtioFSRequestQ, 5, ramBase+testDataAddr+640, uint32(len(response)), vringDescFWrite, 0)
	copy(ram[testDataAddr+512:], request)
	availPush(NewRAM(ram, ramBase), virtioFSRequestQ, 4)
	core.MMIOWrite(0x050, virtioFSRequestQ)
	deadline := time.Now().Add(5 * time.Second)
	for usedIndex(NewRAM(ram, ramBase), virtioFSRequestQ) != 3 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := usedIndex(NewRAM(ram, ramBase), virtioFSRequestQ); got != 3 {
		t.Fatalf("suppressed completion used index = %d, want 3", got)
	}
	select {
	case <-irq:
		t.Fatal("EVENT_IDX-suppressed completion raised an interrupt")
	case <-time.After(25 * time.Millisecond):
	}

	setAvailUsedEvent(NewRAM(ram, ramBase), virtioFSRequestQ, 8, 3)
	putDesc(NewRAM(ram, ramBase), virtioFSRequestQ, 6, ramBase+testDataAddr+768, uint32(len(request)), vringDescFNext, 7)
	putDesc(NewRAM(ram, ramBase), virtioFSRequestQ, 7, ramBase+testDataAddr+896, uint32(len(response)), vringDescFWrite, 0)
	copy(ram[testDataAddr+768:], request)
	availPush(NewRAM(ram, ramBase), virtioFSRequestQ, 6)
	core.MMIOWrite(0x050, virtioFSRequestQ)
	select {
	case <-irq:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for rearmed EVENT_IDX interrupt")
	}

	if err := core.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-serverErr:
		if err != nil {
			t.Fatalf("vhost backend shutdown: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("vhost backend did not stop")
	}
}
