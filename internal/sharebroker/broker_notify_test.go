package sharebroker

import (
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/ejpir/gantry/internal/fusewire"

	"github.com/hanwen/go-fuse/v2/fuse"
)

type brokerNotificationHandler struct {
	mu             sync.Mutex
	sink           fusewire.NotificationSink
	ready          chan struct{}
	requestStarted chan struct{}
	requestRelease chan struct{}
}

func (h *brokerNotificationHandler) HandleRequest(_ [][]byte, out [][]byte) (int, fuse.Status) {
	if h.requestStarted != nil {
		select {
		case h.requestStarted <- struct{}{}:
		default:
		}
		<-h.requestRelease
	}
	if len(out) == 0 || len(out[0]) == 0 {
		return 0, fuse.EIO
	}
	out[0][0] = 0x5a
	return 1, fuse.OK
}

func (h *brokerNotificationHandler) SetNotificationSink(sink fusewire.NotificationSink) {
	h.mu.Lock()
	h.sink = sink
	h.mu.Unlock()
	if sink != nil {
		select {
		case h.ready <- struct{}{}:
		default:
		}
	}
}

func (h *brokerNotificationHandler) notificationSink() fusewire.NotificationSink {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.sink
}

func brokerEpochNotification() []byte {
	message := make([]byte, 16)
	binary.LittleEndian.PutUint32(message[0:4], uint32(len(message)))
	code := int32(-fuse.NOTIFY_INC_EPOCH)
	binary.LittleEndian.PutUint32(message[4:8], uint32(code))
	return message
}

func TestBrokerCarriesReverseNotificationsWhileIdle(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	handler := &brokerNotificationHandler{ready: make(chan struct{}, 1)}
	serverDone := make(chan error, 1)
	go func() { serverDone <- Serve(serverConn, handler) }()
	client, err := NewClient(clientConn)
	if err != nil {
		t.Fatal(err)
	}

	received := make(chan []byte, 1)
	client.SetNotificationSink(func(message []byte) fuse.Status {
		received <- append([]byte(nil), message...)
		return fuse.OK
	})
	select {
	case <-handler.ready:
	case <-time.After(time.Second):
		t.Fatal("server did not attach notification source")
	}

	message := brokerEpochNotification()
	if status := handler.notificationSink()(message); status != fuse.OK {
		t.Fatalf("notification status = %v", status)
	}
	select {
	case got := <-received:
		if string(got) != string(message) {
			t.Fatalf("notification = %x, want %x", got, message)
		}
	case <-time.After(time.Second):
		t.Fatal("idle client did not receive notification")
	}

	in := make([]byte, fusewire.InHeaderSize)
	out := make([]byte, 16)
	if n, status := client.HandleRequest([][]byte{in}, [][]byte{out}); n != 1 || status != fuse.OK || out[0] != 0x5a {
		t.Fatalf("request after notification = n%d status=%v out=%x", n, status, out[:1])
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not stop")
	}
}

func TestBrokerOrdersNotificationAfterMutatingResponse(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	handler := &brokerNotificationHandler{
		ready:          make(chan struct{}, 1),
		requestStarted: make(chan struct{}, 1),
		requestRelease: make(chan struct{}),
	}
	serverDone := make(chan error, 1)
	go func() { serverDone <- Serve(serverConn, handler) }()
	client, err := NewClient(clientConn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = client.Close()
		<-serverDone
	}()

	received := make(chan []byte, 1)
	client.SetNotificationSink(func(message []byte) fuse.Status {
		received <- append([]byte(nil), message...)
		return fuse.OK
	})
	select {
	case <-handler.ready:
	case <-time.After(time.Second):
		t.Fatal("server did not attach notification source")
	}

	requestDone := make(chan struct{})
	go func() {
		defer close(requestDone)
		in := make([]byte, fusewire.InHeaderSize)
		out := make([]byte, 16)
		if n, status := client.HandleRequest([][]byte{in}, [][]byte{out}); n != 1 || status != fuse.OK {
			t.Errorf("request = n%d status=%v", n, status)
		}
	}()
	select {
	case <-handler.requestStarted:
	case <-time.After(time.Second):
		t.Fatal("request did not reach handler")
	}
	if status := handler.notificationSink()(brokerEpochNotification()); status != fuse.OK {
		t.Fatalf("notification status = %v", status)
	}
	select {
	case <-received:
		t.Fatal("notification overtook the in-flight FUSE response")
	case <-time.After(25 * time.Millisecond):
	}
	close(handler.requestRelease)
	select {
	case <-requestDone:
	case <-time.After(time.Second):
		t.Fatal("request did not complete")
	}
	select {
	case <-received:
	case <-time.After(time.Second):
		t.Fatal("ordered notification was not delivered")
	}
}
