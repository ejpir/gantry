//go:build linux || darwin

package virtio

import (
	"encoding/binary"
	"sync"
	"testing"
	"time"

	"github.com/ejpir/gantry/internal/fusewire"

	"github.com/hanwen/go-fuse/v2/fuse"
)

type notificationTestHandler struct {
	mu   sync.Mutex
	sink fusewire.NotificationSink
}

type reentrantNotificationHandler struct {
	notificationTestHandler
	result chan fuse.Status
}

func (h *reentrantNotificationHandler) HandleRequest([][]byte, [][]byte) (int, fuse.Status) {
	sink := h.notificationSink()
	if sink == nil {
		h.result <- fuse.ENOSYS
	} else {
		h.result <- sink(epochNotification())
	}
	return 0, fuse.EIO
}

func (*notificationTestHandler) HandleRequest([][]byte, [][]byte) (int, fuse.Status) {
	return 0, fuse.EIO
}

func (h *notificationTestHandler) SetNotificationSink(sink fusewire.NotificationSink) {
	h.mu.Lock()
	h.sink = sink
	h.mu.Unlock()
}

func (h *notificationTestHandler) notificationSink() fusewire.NotificationSink {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.sink
}

func epochNotification() []byte {
	message := make([]byte, 16)
	binary.LittleEndian.PutUint32(message[0:4], uint32(len(message)))
	code := int32(-fuse.NOTIFY_INC_EPOCH)
	binary.LittleEndian.PutUint32(message[4:8], uint32(code))
	return message
}

func waitUsed(t *testing.T, mem *RAM, queue uint32) usedElem {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if used, ok := usedPop(mem, queue); ok {
			return used
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("queue %d did not publish a used element", queue)
	return usedElem{}
}

func TestVirtioFSNotificationQueue(t *testing.T) {
	handler := new(notificationTestHandler)
	device, err := NewFS("notify", handler, nil)
	if err != nil {
		t.Fatal(err)
	}
	ram := make([]byte, 4<<20)
	mem := NewRAM(ram, ramBase)
	irq := &irqRec{raised: make(map[int]bool)}
	core := NewCoreAt(device, mem, MMIOBaseArm64, MMIOIRQArm64, irq.line, "notify")
	defer func() { _ = core.Close() }()

	if got := core.MMIORead(0x010, 4); got&uint32(virtioFSFGantryNotification) == 0 {
		t.Fatalf("notification feature missing from %#x", got)
	}
	core.MMIOWrite(0x020, uint32(virtioFSFGantryNotification))
	setupQueue(mem, core, virtioFSNotificationQ, 8)
	bufferAddress := uint64(ramBase + testDataAddr + 0x8000)
	putDesc(mem, virtioFSNotificationQ, 0, bufferAddress, fusewire.MaxNotificationBytes, vringDescFWrite, 0)
	availPush(mem, virtioFSNotificationQ, 0)
	core.MMIOWrite(0x050, virtioFSNotificationQ)

	sink := handler.notificationSink()
	if sink == nil {
		t.Fatal("notification source was not attached after guest buffer")
	}
	message := epochNotification()
	if status := sink(message); status != fuse.OK {
		t.Fatalf("notification status = %v", status)
	}
	used := waitUsed(t, mem, virtioFSNotificationQ)
	if used.id != 0 || used.len != uint32(len(message)) {
		t.Fatalf("used = %+v", used)
	}
	got := make([]byte, len(message))
	if err := mem.readAt(bufferAddress, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(message) {
		t.Fatalf("notification = %x, want %x", got, message)
	}
	if !irq.isRaised(MMIOIRQArm64) {
		t.Fatal("notification completion did not raise IRQ")
	}

	core.MMIOWrite(0x070, 0)
	if handler.notificationSink() != nil {
		t.Fatal("device reset did not detach notification source")
	}
}

func TestVirtioFSNotificationEmittedFromRequestDoesNotDeadlock(t *testing.T) {
	handler := &reentrantNotificationHandler{result: make(chan fuse.Status, 1)}
	device, err := NewFS("notify-reentrant", handler, nil)
	if err != nil {
		t.Fatal(err)
	}
	ram := make([]byte, 4<<20)
	mem := NewRAM(ram, ramBase)
	irq := &irqRec{raised: make(map[int]bool)}
	core := NewCoreAt(device, mem, MMIOBaseArm64, MMIOIRQArm64, irq.line, "notify-reentrant")
	defer func() { _ = core.Close() }()

	core.MMIOWrite(0x020, uint32(virtioFSFGantryNotification))
	setupQueue(mem, core, virtioFSNotificationQ, 8)
	notificationAddress := uint64(ramBase + testDataAddr + 0x8000)
	putDesc(mem, virtioFSNotificationQ, 0, notificationAddress, fusewire.MaxNotificationBytes, vringDescFWrite, 0)
	availPush(mem, virtioFSNotificationQ, 0)
	core.MMIOWrite(0x050, virtioFSNotificationQ)

	setupQueue(mem, core, virtioFSRequestQ, 8)
	requestAddress := uint64(ramBase + testDataAddr)
	responseAddress := requestAddress + 0x100
	if err := mem.writeAt(requestAddress, make([]byte, fusewire.InHeaderSize)); err != nil {
		t.Fatal(err)
	}
	putDesc(mem, virtioFSRequestQ, 0, requestAddress, fusewire.InHeaderSize, vringDescFNext, 1)
	putDesc(mem, virtioFSRequestQ, 1, responseAddress, 16, vringDescFWrite, 0)
	availPush(mem, virtioFSRequestQ, 0)

	done := make(chan struct{})
	go func() {
		core.MMIOWrite(0x050, virtioFSRequestQ)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("request-triggered notification deadlocked Core.mu")
	}
	if status := <-handler.result; status != fuse.OK {
		t.Fatalf("notification status = %v, want OK", status)
	}
	used := waitUsed(t, mem, virtioFSNotificationQ)
	if used.id != 0 || used.len != uint32(len(epochNotification())) {
		t.Fatalf("notification used element = %+v", used)
	}
}
