//go:build linux || darwin || windows

package sharebroker

import (
	"encoding/binary"
	"io"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/ejpir/gantry/internal/fusewire"

	"github.com/hanwen/go-fuse/v2/fuse"
)

type brokerTestHandler struct {
	mu      sync.Mutex
	shapes  [][]int
	panicOn byte
}

func brokerInput(marker byte) []byte {
	in := make([]byte, fusewire.InHeaderSize)
	in[0] = marker
	return in
}

func (h *brokerTestHandler) HandleRequest(in, out [][]byte) (int, fuse.Status) {
	if len(in) > 0 && len(in[0]) > 0 && in[0][0] == h.panicOn && h.panicOn != 0 {
		panic("malformed FUSE request")
	}
	shape := make([]int, 0, len(in)+len(out)+1)
	for _, b := range in {
		shape = append(shape, len(b))
	}
	shape = append(shape, -1)
	for _, b := range out {
		shape = append(shape, len(b))
	}
	h.mu.Lock()
	h.shapes = append(h.shapes, shape)
	h.mu.Unlock()

	if len(in) > 0 && len(in[0]) > 0 && in[0][0] == 0xee {
		return 0, fuse.EROFS
	}
	payload := []byte("abcdefgh")
	off := 0
	for _, b := range out {
		off += copy(b, payload[off:])
		if off == len(payload) {
			break
		}
	}
	return off, fuse.OK
}

func TestRoundTripPreservesIOVShape(t *testing.T) {
	handler := &brokerTestHandler{}
	server, client := net.Pipe()
	serveErr := make(chan error, 1)
	go func() { serveErr <- Serve(server, handler) }()

	proxy, err := NewClient(client)
	if err != nil {
		t.Fatal(err)
	}
	in := [][]byte{make([]byte, 20), make([]byte, 27)}
	out := [][]byte{make([]byte, 3), make([]byte, 7)}
	n, status := proxy.HandleRequest(in, out)
	if status != fuse.OK || n != 8 {
		t.Fatalf("round trip = n %d status %v, want 8/OK", n, status)
	}
	if got := string(append(append([]byte(nil), out[0]...), out[1]...)); got != "abcdefgh\x00\x00" {
		t.Fatalf("output = %q", got)
	}
	handler.mu.Lock()
	gotShape := append([]int(nil), handler.shapes[0]...)
	handler.mu.Unlock()
	wantShape := []int{20, 27, -1, 3, 7}
	if len(gotShape) != len(wantShape) {
		t.Fatalf("IOV shape = %v, want %v", gotShape, wantShape)
	}
	for i := range wantShape {
		if gotShape[i] != wantShape[i] {
			t.Fatalf("IOV shape = %v, want %v", gotShape, wantShape)
		}
	}

	// A valid FUSE errno is a normal response, not a transport failure;
	// the same connection remains usable afterward.
	if n, status = proxy.HandleRequest([][]byte{brokerInput(0xee)}, [][]byte{make([]byte, 16)}); n != 0 || status != fuse.EROFS {
		t.Fatalf("error round trip = n %d status %v, want 0/EROFS", n, status)
	}
	if n, status = proxy.HandleRequest([][]byte{brokerInput(1)}, [][]byte{make([]byte, 8)}); n != 8 || status != fuse.OK {
		t.Fatalf("post-error round trip = n %d status %v, want 8/OK", n, status)
	}

	if err := proxy.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-serveErr; err != nil {
		t.Fatalf("ServeBroker after peer close: %v", err)
	}
}

type brokerNoReplyHandler struct{}

func (brokerNoReplyHandler) HandleRequest(_, _ [][]byte) (int, fuse.Status) {
	// go-fuse can return its internal OutHeader length even when a FUSE
	// no-reply request supplied no writable descriptor.
	return 16, fuse.OK
}

func TestAcceptsNoReplyRequest(t *testing.T) {
	server, client := net.Pipe()
	serveErr := make(chan error, 1)
	go func() { serveErr <- Serve(server, brokerNoReplyHandler{}) }()

	proxy, err := NewClient(client)
	if err != nil {
		t.Fatal(err)
	}
	if n, status := proxy.HandleRequest([][]byte{brokerInput(1)}, nil); n != 0 || status != fuse.OK {
		t.Fatalf("no-reply round trip = n %d status %v, want 0/OK", n, status)
	}
	if err := proxy.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-serveErr; err != nil {
		t.Fatalf("ServeBroker after no-reply request: %v", err)
	}
}

type brokerSpyRWC struct {
	writes int
	closed bool
}

func (s *brokerSpyRWC) Read([]byte) (int, error) { return 0, io.EOF }
func (s *brokerSpyRWC) Write(p []byte) (int, error) {
	s.writes += len(p)
	return len(p), nil
}
func (s *brokerSpyRWC) Close() error { s.closed = true; return nil }

type brokerOwnedSpyRWC struct {
	closed chan struct{}
	once   sync.Once
}

func newBrokerOwnedSpyRWC() *brokerOwnedSpyRWC {
	return &brokerOwnedSpyRWC{closed: make(chan struct{})}
}

func (s *brokerOwnedSpyRWC) Read([]byte) (int, error) {
	<-s.closed
	return 0, io.EOF
}

func (s *brokerOwnedSpyRWC) Write(p []byte) (int, error) { return len(p), nil }

func (s *brokerOwnedSpyRWC) Close() error {
	s.once.Do(func() { close(s.closed) })
	return nil
}

func (s *brokerOwnedSpyRWC) isClosed() bool {
	select {
	case <-s.closed:
		return true
	default:
		return false
	}
}

func TestClientRejectsOversizedRequestBeforeWrite(t *testing.T) {
	stream := &brokerSpyRWC{}
	proxy, err := NewClient(stream)
	if err != nil {
		t.Fatal(err)
	}
	n, status := proxy.HandleRequest(
		[][]byte{make([]byte, MaxMessageBytes)},
		[][]byte{make([]byte, 1)},
	)
	if n != 0 || status != fuse.EIO {
		t.Fatalf("oversized request = n %d status %v, want 0/EIO", n, status)
	}
	if stream.writes != 0 {
		t.Fatalf("oversized request wrote %d transport bytes", stream.writes)
	}
	if !stream.closed {
		t.Fatal("oversized request did not terminate transport")
	}
}

func TestClientRejectsMalformedFUSEShapeBeforeWrite(t *testing.T) {
	stream := &brokerSpyRWC{}
	proxy, err := NewClient(stream)
	if err != nil {
		t.Fatal(err)
	}
	n, status := proxy.HandleRequest([][]byte{make([]byte, fusewire.InHeaderSize-1)}, nil)
	if n != 0 || status != fuse.EIO {
		t.Fatalf("malformed request = n %d status %v, want 0/EIO", n, status)
	}
	if stream.writes != 0 {
		t.Fatalf("malformed request wrote %d transport bytes", stream.writes)
	}
	if !stream.closed {
		t.Fatal("malformed request did not terminate transport")
	}
}

func TestClientOwnsTransport(t *testing.T) {
	stream := newBrokerOwnedSpyRWC()
	proxy, err := NewClient(stream)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = proxy.Close() })
	if stream.isClosed() {
		t.Fatal("constructing the client closed the broker transport")
	}
	if err := proxy.Close(); err != nil {
		t.Fatal(err)
	}
	if !stream.isClosed() {
		t.Fatal("owning proxy Close did not close the broker transport")
	}
}

func TestServeRejectsMalformedCounts(t *testing.T) {
	server, client := net.Pipe()
	serveErr := make(chan error, 1)
	go func() { serveErr <- Serve(server, &brokerTestHandler{}) }()

	var hdr [shareBrokerHeaderSize]byte
	putShareBrokerHeader(hdr[:], shareBrokerRequest, 1)
	binary.BigEndian.PutUint16(hdr[16:18], shareBrokerMaxIOVs+1)
	if err := writeBrokerAll(client, hdr[:]); err != nil {
		t.Fatal(err)
	}
	err := <-serveErr
	if err == nil || !strings.Contains(err.Error(), "invalid IOV counts") {
		t.Fatalf("ServeBroker error = %v, want invalid IOV counts", err)
	}
	_ = client.Close()
}

func TestServeRejectsTruncatedInput(t *testing.T) {
	server, client := net.Pipe()
	serveErr := make(chan error, 1)
	go func() { serveErr <- Serve(server, &brokerTestHandler{}) }()

	var hdr [shareBrokerHeaderSize]byte
	putShareBrokerHeader(hdr[:], shareBrokerRequest, 1)
	binary.BigEndian.PutUint16(hdr[16:18], 1)
	binary.BigEndian.PutUint32(hdr[20:24], 4)
	if err := writeBrokerAll(client, hdr[:]); err != nil {
		t.Fatal(err)
	}
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], 4)
	if err := writeBrokerAll(client, length[:]); err != nil {
		t.Fatal(err)
	}
	if err := writeBrokerAll(client, []byte{1, 2}); err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	if err := <-serveErr; err == nil || !strings.Contains(err.Error(), "input") {
		t.Fatalf("ServeBroker truncated input = %v", err)
	}
}

func TestServeRejectsMalformedFUSEShape(t *testing.T) {
	handler := &brokerTestHandler{}
	server, client := net.Pipe()
	serveErr := make(chan error, 1)
	go func() { serveErr <- Serve(server, handler) }()

	var hdr [shareBrokerHeaderSize]byte
	putShareBrokerHeader(hdr[:], shareBrokerRequest, 1)
	binary.BigEndian.PutUint16(hdr[16:18], 1)
	binary.BigEndian.PutUint32(hdr[20:24], fusewire.InHeaderSize-1)
	if err := writeBrokerAll(client, hdr[:]); err != nil {
		t.Fatal(err)
	}
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], fusewire.InHeaderSize-1)
	if err := writeBrokerAll(client, length[:]); err != nil {
		t.Fatal(err)
	}
	if err := writeBrokerAll(client, make([]byte, fusewire.InHeaderSize-1)); err != nil {
		t.Fatal(err)
	}
	if err := <-serveErr; err == nil || !strings.Contains(err.Error(), "malformed FUSE input shape") {
		t.Fatalf("ServeBroker malformed shape = %v", err)
	}
	handler.mu.Lock()
	defer handler.mu.Unlock()
	if len(handler.shapes) != 0 {
		t.Fatalf("malformed request reached handler: %v", handler.shapes)
	}
	_ = client.Close()
}

func TestClientRejectsWrongResponseID(t *testing.T) {
	server, client := net.Pipe()
	serverErr := make(chan error, 1)
	go func() {
		var hdr [shareBrokerHeaderSize]byte
		var frame brokerFrame
		if _, err := io.ReadFull(server, hdr[:]); err != nil {
			serverErr <- err
			return
		}
		_, inLens, _, err := readShareBrokerRequest(server, hdr[:], 0, &frame.lengths, &frame.wireLengths)
		if err == nil {
			_, err = frame.readInput(server, inLens)
		}
		if err == nil {
			err = writeShareBrokerResponse(server, 2, fuse.OK, nil, &frame.header, &frame.responseVectors, &frame.responseBuffers)
		}
		serverErr <- err
	}()
	proxy, err := NewClient(client)
	if err != nil {
		t.Fatal(err)
	}
	if n, status := proxy.HandleRequest([][]byte{brokerInput(1)}, nil); n != 0 || status != fuse.EIO {
		t.Fatalf("wrong response ID = n %d status %v, want 0/EIO", n, status)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
	_ = proxy.Close()
	_ = server.Close()
}

func TestServeContainsHandlerPanic(t *testing.T) {
	server, client := net.Pipe()
	serveErr := make(chan error, 1)
	go func() { serveErr <- Serve(server, &brokerTestHandler{panicOn: 0xff}) }()
	proxy, err := NewClient(client)
	if err != nil {
		t.Fatal(err)
	}

	n, status := proxy.HandleRequest([][]byte{brokerInput(0xff)}, [][]byte{make([]byte, 16)})
	if n != 0 || status != fuse.EIO {
		t.Fatalf("panic request = n %d status %v, want 0/EIO", n, status)
	}
	if err := <-serveErr; err == nil || !strings.Contains(err.Error(), "FUSE handler panic") {
		t.Fatalf("ServeBroker error = %v, want contained panic", err)
	}
	_ = proxy.Close()
}

func BenchmarkRoundTrip(b *testing.B) {
	handler := benchmarkHandler{}
	server, transport := net.Pipe()
	serveErr := make(chan error, 1)
	go func() { serveErr <- Serve(server, handler) }()
	client, err := NewClient(transport)
	if err != nil {
		b.Fatal(err)
	}
	in := [][]byte{make([]byte, 40), make([]byte, 128)}
	out := [][]byte{make([]byte, 16), make([]byte, 4096)}
	b.ReportAllocs()
	b.SetBytes(int64(len(in[0]) + len(in[1]) + len(out[0]) + len(out[1])))
	b.ResetTimer()
	for range b.N {
		if _, status := client.HandleRequest(in, out); status != fuse.OK {
			b.Fatalf("round trip status %v", status)
		}
	}
	b.StopTimer()
	if err := client.Close(); err != nil {
		b.Fatal(err)
	}
	if err := <-serveErr; err != nil {
		b.Fatal(err)
	}
}

type benchmarkHandler struct{}

func (benchmarkHandler) HandleRequest(_ [][]byte, out [][]byte) (int, fuse.Status) {
	if len(out) == 0 {
		return 0, fuse.OK
	}
	copy(out[0], "benchmark")
	return min(len(out[0]), len("benchmark")), fuse.OK
}
