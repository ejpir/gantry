//go:build linux || darwin

package virtio

import (
	"encoding/binary"
	"sync"
	"testing"

	"github.com/ejpir/gantry/internal/fusewire"

	"github.com/hanwen/go-fuse/v2/fuse"
)

type notificationTestHandler struct {
	mu   sync.Mutex
	sink fusewire.NotificationSink
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
	code := int32(fuse.NOTIFY_INC_EPOCH)
	binary.LittleEndian.PutUint32(message[4:8], uint32(code))
	return message
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
	used, ok := usedPop(mem, virtioFSNotificationQ)
	if !ok || used.id != 0 || used.len != uint32(len(message)) {
		t.Fatalf("used = %+v, %v", used, ok)
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
