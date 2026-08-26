//go:build linux || darwin

package virtio

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/ejpir/gantry/internal/fusewire"
	"github.com/ejpir/gantry/internal/sharefs"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/hanwen/go-fuse/v2/virtiofs"
)

type vhostWireGuest struct {
	t          *testing.T
	ram        []byte
	mem        *RAM
	core       *Core
	irq        chan struct{}
	usedIdx    uint16
	unique     uint64
	indirect   bool
	noOpenDir  bool
	notifyUsed uint16
}

const vhostWireRAMSize = 4 << 20

func attachVhostWireGuest(t *testing.T, file *os.File, ram []byte, frontend net.Conn, queues []VhostQueueFiles) *vhostWireGuest {
	t.Helper()
	endpoint, err := NewVhostEndpoint(frontend, queues)
	if err != nil {
		t.Fatal(err)
	}
	device, err := endpoint.NewDevice("vhost-wire", file, ramBase, vhostWireRAMSize)
	if err != nil {
		t.Fatal(err)
	}
	guest := &vhostWireGuest{t: t, ram: ram, mem: NewRAM(ram, ramBase), irq: make(chan struct{}, 8), indirect: true}
	guest.core = NewCoreAt(device, guest.mem, MMIOBaseArm64, MMIOIRQArm64,
		func(_ int, level bool) {
			if level {
				select {
				case guest.irq <- struct{}{}:
				default:
				}
			}
		}, "vhost-wire")
	setupQueue(guest.mem, guest.core, virtioFSRequestQ, 8)
	guest.core.MMIOWrite(0x020, uint32(virtioFSFGantryNotification|vhostRingIndirectDesc|vhostRingEventIdx))
	return guest
}

func serveVhostWire(conn *net.UnixConn, handler fusewire.Handler) error {
	return virtiofs.ServeConn(conn, func(in, out [][]byte) int {
		n, status := handler.HandleRequest(in, out)
		if len(out) == 0 {
			return 0
		}
		if status != fuse.OK {
			return fusewire.WriteError(in, out, status)
		}
		capacity := 0
		for _, part := range out {
			capacity += len(part)
		}
		if n < 0 || n > capacity {
			return fusewire.WriteError(in, out, fuse.EIO)
		}
		return n
	}, false, func(sink func([]byte) fuse.Status) {
		if source, ok := handler.(fusewire.NotificationSource); ok {
			source.SetNotificationSink(sink)
		}
	})
}

type synchronousVhostNotifier struct {
	mu    sync.Mutex
	sink  fusewire.NotificationSink
	ready chan struct{}
	once  sync.Once
}

func newSynchronousVhostNotifier() *synchronousVhostNotifier {
	return &synchronousVhostNotifier{ready: make(chan struct{})}
}

func (h *synchronousVhostNotifier) SetNotificationSink(sink fusewire.NotificationSink) {
	h.mu.Lock()
	h.sink = sink
	h.mu.Unlock()
	if sink != nil {
		h.once.Do(func() { close(h.ready) })
	}
}

func (h *synchronousVhostNotifier) HandleRequest(in, out [][]byte) (int, fuse.Status) {
	h.mu.Lock()
	sink := h.sink
	h.mu.Unlock()
	if sink == nil {
		return 0, fuse.EIO
	}
	message := make([]byte, 32) // header + empty fuse_notify_prune_out
	binary.LittleEndian.PutUint32(message[0:4], uint32(len(message)))
	binary.LittleEndian.PutUint32(message[4:8], 9) // FUSE_NOTIFY_PRUNE
	if status := sink(message); status != fuse.OK {
		return 0, status
	}
	return fusewire.WriteError(in, out, fuse.OK), fuse.OK
}

func newVhostWireGuest(t *testing.T, handler fusewire.Handler) (*vhostWireGuest, func()) {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "vhost-wire-ram-*")
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(vhostWireRAMSize); err != nil {
		t.Fatal(err)
	}
	ram, err := syscall.Mmap(int(file.Fd()), 0, vhostWireRAMSize,
		syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		t.Fatal(err)
	}
	frontend, backend := testUnixConnPair(t)
	guest := attachVhostWireGuest(t, file, ram, frontend, testVhostQueues(t))
	serverErr := make(chan error, 1)
	go func() { serverErr <- serveVhostWire(backend, handler) }()

	cleanup := func() {
		_ = guest.core.Close()
		select {
		case err := <-serverErr:
			if err != nil {
				t.Errorf("vhost backend shutdown: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("vhost backend did not stop")
		}
		_ = syscall.Munmap(ram)
	}
	return guest, cleanup
}

func (g *vhostWireGuest) request(opcode uint32, nodeID uint64, payload []byte, outputSizes ...int) (int32, [][]byte) {
	g.t.Helper()
	g.unique++
	header := make([]byte, 40)
	binary.LittleEndian.PutUint32(header[0:4], uint32(len(header)+len(payload)))
	binary.LittleEndian.PutUint32(header[4:8], opcode)
	binary.LittleEndian.PutUint64(header[8:16], g.unique)
	binary.LittleEndian.PutUint64(header[16:24], nodeID)

	inputs := [][]byte{header}
	if len(payload) != 0 {
		inputs = append(inputs, payload)
	}
	descriptorCount := len(inputs) + len(outputSizes)
	if descriptorCount == 0 || descriptorCount > 8 {
		g.t.Fatalf("descriptor count %d", descriptorCount)
	}

	type descriptor struct {
		address uint64
		length  uint32
		flags   uint16
		next    uint16
	}
	descriptors := make([]descriptor, 0, descriptorCount)
	// Reserve space for the largest indirect table before request buffers.
	cursor := uint64(testDataAddr + 8*16)
	for _, input := range inputs {
		address := ramBase + cursor
		if err := g.mem.writeAt(address, input); err != nil {
			g.t.Fatal(err)
		}
		descriptors = append(descriptors, descriptor{address: address, length: uint32(len(input))})
		cursor = (cursor + uint64(len(input)) + 7) &^ 7
	}
	outputAddresses := make([]uint64, len(outputSizes))
	for index, size := range outputSizes {
		address := ramBase + cursor
		outputAddresses[index] = address
		descriptors = append(descriptors, descriptor{address: address, length: uint32(size), flags: vringDescFWrite})
		if err := g.mem.writeAt(address, make([]byte, size)); err != nil {
			g.t.Fatal(err)
		}
		cursor = (cursor + uint64(size) + 7) &^ 7
	}
	for index := range descriptors {
		if index+1 < len(descriptors) {
			descriptors[index].flags |= vringDescFNext
			descriptors[index].next = uint16(index + 1)
		}
	}
	if g.indirect {
		table := make([]byte, len(descriptors)*16)
		for index, descriptor := range descriptors {
			entry := table[index*16 : (index+1)*16]
			binary.LittleEndian.PutUint64(entry[0:8], descriptor.address)
			binary.LittleEndian.PutUint32(entry[8:12], descriptor.length)
			binary.LittleEndian.PutUint16(entry[12:14], descriptor.flags)
			binary.LittleEndian.PutUint16(entry[14:16], descriptor.next)
		}
		tableAddress := uint64(ramBase + testDataAddr)
		if err := g.mem.writeAt(tableAddress, table); err != nil {
			g.t.Fatal(err)
		}
		putDesc(g.mem, virtioFSRequestQ, 0, tableAddress, uint32(len(table)), vringDescFIndirect, 0)
	} else {
		for index, descriptor := range descriptors {
			putDesc(g.mem, virtioFSRequestQ, uint16(index), descriptor.address, descriptor.length, descriptor.flags, descriptor.next)
		}
	}

	wantUsed := g.usedIdx + 1
	setAvailUsedEvent(g.mem, virtioFSRequestQ, 8, g.usedIdx)
	availPush(g.mem, virtioFSRequestQ, 0)
	g.core.MMIOWrite(0x050, virtioFSRequestQ)
	deadline := time.Now().Add(5 * time.Second)
	usedAddress := ramBase + testUsedAddr + uint64(virtioFSRequestQ)*testStride
	for time.Now().Before(deadline) {
		var index [2]byte
		if err := g.mem.readAt(usedAddress+2, index[:]); err != nil {
			g.t.Fatal(err)
		}
		if binary.LittleEndian.Uint16(index[:]) == wantUsed {
			break
		}
		select {
		case <-g.irq:
		case <-time.After(time.Millisecond):
		}
	}
	var index [2]byte
	if err := g.mem.readAt(usedAddress+2, index[:]); err != nil {
		g.t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint16(index[:]); got != wantUsed {
		g.t.Fatalf("op %d unique %d: used index %d, want %d", opcode, g.unique, got, wantUsed)
	}
	var used [8]byte
	usedSlot := usedAddress + 4 + uint64(g.usedIdx%8)*8
	if err := g.mem.readAt(usedSlot, used[:]); err != nil {
		g.t.Fatal(err)
	}
	written := int(binary.LittleEndian.Uint32(used[4:8]))
	g.usedIdx = wantUsed
	g.core.MMIOWrite(0x064, virtioIntUsedBuffer)

	outputs := make([][]byte, len(outputSizes))
	remaining := written
	for outputIndex, size := range outputSizes {
		usedSize := min(size, max(remaining, 0))
		outputs[outputIndex] = make([]byte, usedSize)
		if usedSize != 0 {
			if err := g.mem.readAt(outputAddresses[outputIndex], outputs[outputIndex]); err != nil {
				g.t.Fatal(err)
			}
		}
		remaining -= usedSize
	}
	if len(outputs) == 0 || len(outputs[0]) < 8 {
		return 0, outputs
	}
	return int32(binary.LittleEndian.Uint32(outputs[0][4:8])), outputs
}

func fusePayload(size int) []byte { return make([]byte, size) }

func (g *vhostWireGuest) init() {
	g.t.Helper()
	payload := fusePayload(64)
	binary.LittleEndian.PutUint32(payload[0:4], 7)
	binary.LittleEndian.PutUint32(payload[4:8], 45)
	capabilities := uint64(fuse.CAP_READDIRPLUS | fuse.CAP_READDIRPLUS_AUTO | fuse.CAP_NO_OPENDIR_SUPPORT |
		fuse.CAP_INIT_EXT | fuse.CAP_GANTRY_READDIR_EOF)
	binary.LittleEndian.PutUint32(payload[12:16], uint32(capabilities))
	binary.LittleEndian.PutUint32(payload[16:20], uint32(capabilities>>32))
	errno, _ := g.request(fuse.OpInit, 0, payload, 16, 64)
	if errno != 0 {
		g.t.Fatalf("INIT errno %d", errno)
	}
}

func (g *vhostWireGuest) postNotificationBuffer() uint64 {
	g.t.Helper()
	setupQueue(g.mem, g.core, virtioFSNotificationQ, 8)
	address := uint64(ramBase + testDataAddr + 2*testStride)
	putDesc(g.mem, virtioFSNotificationQ, 0, address, fusewire.MaxNotificationBytes, vringDescFWrite, 0)
	availPush(g.mem, virtioFSNotificationQ, 0)
	g.core.MMIOWrite(0x050, virtioFSNotificationQ)
	return address
}

func (g *vhostWireGuest) waitNotification(address uint64) []byte {
	g.t.Helper()
	wantUsed := g.notifyUsed + 1
	usedAddress := ramBase + testUsedAddr + uint64(virtioFSNotificationQ)*testStride
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var index [2]byte
		if err := g.mem.readAt(usedAddress+2, index[:]); err != nil {
			g.t.Fatal(err)
		}
		if binary.LittleEndian.Uint16(index[:]) == wantUsed {
			break
		}
		select {
		case <-g.irq:
		case <-time.After(time.Millisecond):
		}
	}
	used := usedAt(g.mem, virtioFSNotificationQ, g.notifyUsed)
	if used.id != 0 || used.len < 16 || used.len > fusewire.MaxNotificationBytes {
		g.t.Fatalf("notification used element = %+v", used)
	}
	message := make([]byte, used.len)
	if err := g.mem.readAt(address, message); err != nil {
		g.t.Fatal(err)
	}
	g.notifyUsed = wantUsed
	g.core.MMIOWrite(0x064, virtioIntUsedBuffer)
	return message
}

func (g *vhostWireGuest) lookup(parent uint64, name string) uint64 {
	g.t.Helper()
	errno, out := g.request(fuse.OpLookup, parent, append([]byte(name), 0), 16, 128)
	if errno != 0 {
		g.t.Fatalf("LOOKUP %q errno %d", name, errno)
	}
	if len(out) < 2 || len(out[1]) < 8 {
		g.t.Fatalf("LOOKUP %q short response", name)
	}
	return binary.LittleEndian.Uint64(out[1][0:8])
}

func (g *vhostWireGuest) openDir(node uint64) uint64 {
	g.t.Helper()
	if g.noOpenDir {
		return 0
	}
	errno, out := g.request(fuse.OpOpendir, node, fusePayload(8), 16, 16)
	if errno == -38 { // Linux guest ENOSYS, independent of the host ABI.
		g.noOpenDir = true
		return 0
	}
	if errno != 0 {
		g.t.Fatalf("OPENDIR node %d errno %d", node, errno)
	}
	return binary.LittleEndian.Uint64(out[1][0:8])
}

func (g *vhostWireGuest) readDir(node, handle, offset uint64) ([]fuse.DirEntry, uint64) {
	g.t.Helper()
	const outputSize = 4096
	payload := fusePayload(40)
	binary.LittleEndian.PutUint64(payload[0:8], handle)
	binary.LittleEndian.PutUint64(payload[8:16], offset)
	binary.LittleEndian.PutUint32(payload[16:20], outputSize)
	errno, out := g.request(fuse.OpReaddir, node, payload, 16, outputSize)
	if errno != 0 {
		g.t.Fatalf("READDIR node %d handle %d offset %d errno %d", node, handle, offset, errno)
	}
	if len(out) < 2 {
		return nil, offset
	}
	payloadOut := out[1]
	entries := make([]fuse.DirEntry, 0)
	for len(payloadOut) != 0 {
		if len(payloadOut) < 24 {
			g.t.Fatalf("READDIR trailing %d-byte fragment", len(payloadOut))
		}
		nameLength := int(binary.LittleEndian.Uint32(payloadOut[16:20]))
		if nameLength == 0 && gantryReadDirEOF(payloadOut) {
			if len(payloadOut) != 24 {
				g.t.Fatalf("READDIR EOF marker has %d trailing bytes", len(payloadOut)-24)
			}
			break
		}
		consumed := (24 + nameLength + 7) &^ 7
		if nameLength < 0 || consumed > len(payloadOut) {
			g.t.Fatalf("READDIR invalid name/record length %d/%d", nameLength, len(payloadOut))
		}
		entry := fuse.DirEntry{
			Ino:  binary.LittleEndian.Uint64(payloadOut[0:8]),
			Off:  binary.LittleEndian.Uint64(payloadOut[8:16]),
			Mode: binary.LittleEndian.Uint32(payloadOut[20:24]) << 12,
			Name: string(payloadOut[24 : 24+nameLength]),
		}
		entries = append(entries, entry)
		offset = entry.Off
		payloadOut = payloadOut[consumed:]
	}
	return entries, offset
}

type vhostDirEntry struct {
	fuse.DirEntry
	node uint64
}

func (g *vhostWireGuest) readDirPlus(node, handle, offset uint64) ([]vhostDirEntry, uint64) {
	g.t.Helper()
	const (
		outputSize  = 4096
		entryOutLen = 128
	)
	payload := fusePayload(40)
	binary.LittleEndian.PutUint64(payload[0:8], handle)
	binary.LittleEndian.PutUint64(payload[8:16], offset)
	binary.LittleEndian.PutUint32(payload[16:20], outputSize)
	errno, out := g.request(fuse.OpReaddirplus, node, payload, 16, outputSize)
	if errno != 0 {
		g.t.Fatalf("READDIRPLUS node %d handle %d offset %d errno %d", node, handle, offset, errno)
	}
	if len(out) < 2 {
		return nil, offset
	}
	payloadOut := out[1]
	entries := make([]vhostDirEntry, 0)
	for len(payloadOut) != 0 {
		if len(payloadOut) < entryOutLen+24 {
			g.t.Fatalf("READDIRPLUS trailing %d-byte fragment", len(payloadOut))
		}
		dirent := payloadOut[entryOutLen:]
		nameLength := int(binary.LittleEndian.Uint32(dirent[16:20]))
		if nameLength == 0 && gantryReadDirEOF(dirent) {
			if len(payloadOut) != entryOutLen+24 {
				g.t.Fatalf("READDIRPLUS EOF marker has %d trailing bytes", len(payloadOut)-entryOutLen-24)
			}
			break
		}
		consumed := (entryOutLen + 24 + nameLength + 7) &^ 7
		if nameLength < 0 || consumed > len(payloadOut) {
			g.t.Fatalf("READDIRPLUS invalid name/record length %d/%d", nameLength, len(payloadOut))
		}
		entry := vhostDirEntry{
			node: binary.LittleEndian.Uint64(payloadOut[0:8]),
			DirEntry: fuse.DirEntry{
				Ino:  binary.LittleEndian.Uint64(dirent[0:8]),
				Off:  binary.LittleEndian.Uint64(dirent[8:16]),
				Mode: binary.LittleEndian.Uint32(dirent[20:24]) << 12,
				Name: string(dirent[24 : 24+nameLength]),
			},
		}
		entries = append(entries, entry)
		offset = entry.Off
		payloadOut = payloadOut[consumed:]
	}
	return entries, offset
}

func gantryReadDirEOF(dirent []byte) bool {
	return len(dirent) >= 24 &&
		binary.LittleEndian.Uint64(dirent[0:8]) == fuse.GANTRY_READDIR_EOF_INO &&
		binary.LittleEndian.Uint64(dirent[8:16]) == fuse.GANTRY_READDIR_EOF_OFF &&
		binary.LittleEndian.Uint32(dirent[20:24]) == fuse.GANTRY_READDIR_EOF_TYPE
}

func (g *vhostWireGuest) releaseDir(node, handle uint64) {
	g.t.Helper()
	if g.noOpenDir {
		return
	}
	payload := fusePayload(24)
	binary.LittleEndian.PutUint64(payload[0:8], handle)
	errno, _ := g.request(fuse.OpReleasedir, node, payload, 16)
	if errno != 0 {
		g.t.Fatalf("RELEASEDIR node %d handle %d errno %d", node, handle, errno)
	}
}

const (
	// 22,765 directories approximates the field-failing Zelda tree.
	vhostTreeWidth = 28
	vhostTreeDepth = 3
)

func newVhostTreeHub(t *testing.T) *sharefs.Hub {
	t.Helper()
	root := t.TempDir()
	var populate func(string, int)
	populate = func(parent string, level int) {
		if level == vhostTreeDepth {
			return
		}
		for index := 0; index < vhostTreeWidth; index++ {
			dir := filepath.Join(parent, fmt.Sprintf("d%02d", index))
			if err := os.Mkdir(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "file"), []byte("x"), 0o644); err != nil {
				t.Fatal(err)
			}
			populate(dir, level+1)
		}
	}
	populate(root, 0)

	hub, err := sharefs.NewHub()
	if err != nil {
		t.Fatal(err)
	}
	prepared, _, err := hub.Prepare("tree", root, true)
	if err != nil {
		_ = hub.Close()
		t.Fatal(err)
	}
	if _, err := hub.Publish(prepared); err != nil {
		_ = hub.Close()
		t.Fatal(err)
	}
	return hub
}

func (g *vhostWireGuest) traverseTree() {
	g.t.Helper()
	g.init()
	firstRequest := g.unique
	treeNode := g.lookup(1, "tree")
	type pendingDir struct{ node uint64 }
	pending := []pendingDir{{node: treeNode}}
	visited := 0
	for len(pending) != 0 {
		current := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		handle := g.openDir(current.node)
		offset := uint64(0)
		firstRead := true
		for {
			if firstRead {
				// Linux READDIRPLUS_AUTO uses PLUS at offset zero, then ordinary
				// READDIR for subsequent pages unless a lookup miss advises PLUS.
				entries, next := g.readDirPlus(current.node, handle, offset)
				firstRead = false
				if len(entries) == 0 {
					break
				}
				for _, entry := range entries {
					if entry.Name == "." || entry.Name == ".." {
						continue
					}
					if entry.Mode&syscall.S_IFMT != syscall.S_IFDIR {
						if entry.node != 0 {
							g.t.Fatalf("READDIRPLUS eagerly instantiated non-directory %q as node %d", entry.Name, entry.node)
						}
						continue
					}
					child := entry.node
					if child == 0 {
						child = g.lookup(current.node, entry.Name)
					}
					pending = append(pending, pendingDir{node: child})
				}
				offset = next
				continue
			}

			entries, next := g.readDir(current.node, handle, offset)
			if len(entries) == 0 {
				break
			}
			for _, entry := range entries {
				if entry.Name == "." || entry.Name == ".." || entry.Mode&syscall.S_IFMT != syscall.S_IFDIR {
					continue
				}
				pending = append(pending, pendingDir{node: g.lookup(current.node, entry.Name)})
			}
			offset = next
		}
		g.releaseDir(current.node, handle)
		visited++
	}
	want := 1
	levelWidth := 1
	for level := 0; level < vhostTreeDepth; level++ {
		levelWidth *= vhostTreeWidth
		want += levelWidth
	}
	if visited != want {
		g.t.Fatalf("visited %d directories, want %d", visited, want)
	}
	requests := g.unique - firstRequest
	if requests >= 5*uint64(want) {
		g.t.Fatalf("adaptive traversal used %d requests for %d directories", requests, want)
	}
	g.t.Logf("adaptive traversal: directories=%d requests=%d", want, requests)
}

func TestVhostFSShareHubDirectoryTraversal(t *testing.T) {
	hub := newVhostTreeHub(t)
	defer func() { _ = hub.Close() }()
	guest, cleanup := newVhostWireGuest(t, hub)
	defer cleanup()
	guest.traverseTree()
}

func TestVhostFSShareHubReverseInvalidation(t *testing.T) {
	root := t.TempDir()
	hub, err := sharefs.NewHub()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hub.Close() }()
	prepared, _, err := hub.Prepare("workspace", root, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hub.Publish(prepared); err != nil {
		t.Fatal(err)
	}
	guest, cleanup := newVhostWireGuest(t, hub)
	defer cleanup()
	address := guest.postNotificationBuffer()
	guest.init()
	_ = guest.lookup(1, "workspace")

	if err := exec.Command("touch", filepath.Join(root, "external")).Run(); err != nil {
		t.Fatal(err)
	}
	message := guest.waitNotification(address)
	if !fusewire.ValidNotification(message) {
		t.Fatalf("invalid notification frame: %x", message)
	}
	if code := int32(binary.LittleEndian.Uint32(message[4:8])); code != -fuse.NOTIFY_INVAL_ENTRY {
		t.Fatalf("notification code = %d, want INVAL_ENTRY", code)
	}
}

func TestVhostFSSynchronousNotificationDoesNotDeadlockRequest(t *testing.T) {
	handler := newSynchronousVhostNotifier()
	guest, cleanup := newVhostWireGuest(t, handler)
	defer cleanup()
	notificationAddress := guest.postNotificationBuffer()
	select {
	case <-handler.ready:
	case <-time.After(5 * time.Second):
		t.Fatal("notification sink was not attached")
	}

	// Node-budget pruning emits its reverse notification synchronously from
	// inside the FUSE request handler. The vhost transport must queue delivery
	// until that request releases its completion ordering lock; acquiring the
	// write lock directly here used to deadlock both sides permanently.
	errno, _ := guest.request(fuse.OpGetattr, 1, nil, 16)
	if errno != 0 {
		t.Fatalf("request errno %d", errno)
	}
	message := guest.waitNotification(notificationAddress)
	if code := binary.LittleEndian.Uint32(message[4:8]); code != 9 {
		t.Fatalf("notification code = %d, want FUSE_NOTIFY_PRUNE", code)
	}
}

func TestVhostFSShareHubCrossProcessHelper(t *testing.T) {
	if os.Getenv("GANTRY_VHOST_TEST_HELPER") != "1" {
		t.Skip("cross-process helper")
	}
	memory := os.NewFile(3, "vhost-test-memory")
	controlFile := os.NewFile(4, "vhost-test-control")
	control, err := net.FileConn(controlFile)
	_ = controlFile.Close()
	if err != nil {
		t.Fatal(err)
	}
	queues := make([]VhostQueueFiles, virtioFSQueueCount)
	slot := uintptr(5)
	for index := range queues {
		queues[index] = VhostQueueFiles{
			KickRead:  os.NewFile(slot, fmt.Sprintf("kick-read-%d", index)),
			KickWrite: os.NewFile(slot+1, fmt.Sprintf("kick-write-%d", index)),
			CallRead:  os.NewFile(slot+2, fmt.Sprintf("call-read-%d", index)),
			CallWrite: os.NewFile(slot+3, fmt.Sprintf("call-write-%d", index)),
		}
		slot += 4
	}
	ram, err := syscall.Mmap(int(memory.Fd()), 0, vhostWireRAMSize,
		syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		t.Fatal(err)
	}
	guest := attachVhostWireGuest(t, memory, ram, control, queues)
	guest.traverseTree()
	if err := guest.core.Close(); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Munmap(ram); err != nil {
		t.Fatal(err)
	}
}

func TestVhostFSShareHubCrossProcessTraversal(t *testing.T) {
	hub := newVhostTreeHub(t)
	defer func() { _ = hub.Close() }()
	memory, err := os.CreateTemp(t.TempDir(), "vhost-cross-memory-*")
	if err != nil {
		t.Fatal(err)
	}
	if err := memory.Truncate(vhostWireRAMSize); err != nil {
		t.Fatal(err)
	}
	frontend, backend := testUnixConnPair(t)
	frontendFile, err := frontend.File()
	if err != nil {
		t.Fatal(err)
	}
	_ = frontend.Close()
	queues := testVhostQueues(t)
	extraFiles := []*os.File{memory, frontendFile}
	for _, queue := range queues {
		extraFiles = append(extraFiles, queue.KickRead, queue.KickWrite, queue.CallRead, queue.CallWrite)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestVhostFSShareHubCrossProcessHelper$", "-test.v")
	cmd.Env = append(os.Environ(), "GANTRY_VHOST_TEST_HELPER=1")
	cmd.ExtraFiles = extraFiles
	var childOutput bytes.Buffer
	cmd.Stdout = &childOutput
	cmd.Stderr = &childOutput
	serverErr := make(chan error, 1)
	go func() { serverErr <- serveVhostWire(backend, hub) }()
	if err := cmd.Start(); err != nil {
		_ = backend.Close()
		t.Fatal(err)
	}
	_ = memory.Close()
	_ = frontendFile.Close()
	for _, queue := range queues {
		for _, file := range []*os.File{queue.KickRead, queue.KickWrite, queue.CallRead, queue.CallWrite} {
			_ = file.Close()
		}
	}
	if err := cmd.Wait(); err != nil {
		_ = backend.Close()
		t.Fatalf("vhost child: %v\n%s", err, childOutput.String())
	}
	select {
	case err := <-serverErr:
		if err != nil {
			t.Fatalf("vhost backend: %v\n%s", err, childOutput.String())
		}
	case <-time.After(5 * time.Second):
		_ = backend.Close()
		t.Fatalf("vhost backend did not stop\n%s", childOutput.String())
	}
}
