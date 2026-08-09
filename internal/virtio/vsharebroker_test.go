//go:build linux || darwin || windows

package virtio

import (
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/hanwen/go-fuse/v2/fuse"
)

func proxyRequest(t *testing.T, proxy *ShareHubProxy, in [][]byte, outSizes ...int) (int, int32, [][]byte) {
	t.Helper()
	out := make([][]byte, len(outSizes))
	for i, size := range outSizes {
		out[i] = make([]byte, size)
	}
	n, status := proxy.handler.HandleRequest(in, out)
	if status != fuse.OK {
		t.Fatalf("proxy transport status %v", status)
	}
	if len(out) == 0 || len(out[0]) < 8 {
		return n, 0, out
	}
	return n, int32(binary.LittleEndian.Uint32(out[0][4:8])), out
}

type brokerTestHandler struct {
	mu      sync.Mutex
	shapes  [][]int
	panicOn byte
}

type brokerResourceHandler struct {
	brokerTestHandler
	nodes   int
	handles int
}

func (h *brokerResourceHandler) GantryResourceUsage() (nodes, handles int) {
	return h.nodes, h.handles
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

func testBrokerHub(handler fuseRequestHandler) *ShareHub {
	return &ShareHub{fsTransportDevice: newFSTransportDevice(shareHubTag, handler, false)}
}

func TestShareHubBrokerRoundTripPreservesIOVShape(t *testing.T) {
	handler := &brokerTestHandler{}
	hub := testBrokerHub(handler)
	server, client := net.Pipe()
	serveErr := make(chan error, 1)
	go func() { serveErr <- hub.ServeBroker(server) }()

	proxy, err := NewShareHubProxy(client)
	if err != nil {
		t.Fatal(err)
	}
	in := [][]byte{[]byte("head"), []byte("payload")}
	out := [][]byte{make([]byte, 3), make([]byte, 7)}
	n, status := proxy.handler.HandleRequest(in, out)
	if status != fuse.OK || n != 8 {
		t.Fatalf("round trip = n %d status %v, want 8/OK", n, status)
	}
	if got := string(append(append([]byte(nil), out[0]...), out[1]...)); got != "abcdefgh\x00\x00" {
		t.Fatalf("output = %q", got)
	}
	handler.mu.Lock()
	gotShape := append([]int(nil), handler.shapes[0]...)
	handler.mu.Unlock()
	wantShape := []int{4, 7, -1, 3, 7}
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
	if n, status = proxy.handler.HandleRequest([][]byte{{0xee}}, [][]byte{make([]byte, 16)}); n != 0 || status != fuse.EROFS {
		t.Fatalf("error round trip = n %d status %v, want 0/EROFS", n, status)
	}
	if n, status = proxy.handler.HandleRequest([][]byte{{1}}, [][]byte{make([]byte, 8)}); n != 8 || status != fuse.OK {
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

func TestShareHubBrokerAcceptsNoReplyRequest(t *testing.T) {
	hub := testBrokerHub(brokerNoReplyHandler{})
	server, client := net.Pipe()
	serveErr := make(chan error, 1)
	go func() { serveErr <- hub.ServeBroker(server) }()

	proxy, err := NewShareHubProxy(client)
	if err != nil {
		t.Fatal(err)
	}
	if n, status := proxy.handler.HandleRequest([][]byte{{1}}, nil); n != 0 || status != fuse.OK {
		t.Fatalf("no-reply round trip = n %d status %v, want 0/OK", n, status)
	}
	if err := proxy.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-serveErr; err != nil {
		t.Fatalf("ServeBroker after no-reply request: %v", err)
	}
}

// TestShareHubBrokerRealFUSEPath exercises the actual go-fuse server and
// platform share backend through the relay. In particular, live publication
// remains supervisor-local and a writable OPEN on an RO export is rejected by
// the broker rather than trusted worker metadata.
func TestShareHubBrokerRealFUSEPath(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "hello.txt"), []byte("brokered\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	hub, err := NewShareHub()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hub.Close() }()

	server, client := net.Pipe()
	serveErr := make(chan error, 1)
	go func() { serveErr <- hub.ServeBroker(server) }()
	proxy, err := NewShareHubProxy(client)
	if err != nil {
		t.Fatal(err)
	}

	initPayload := make([]byte, 64)
	binary.LittleEndian.PutUint32(initPayload[0:4], 7)
	binary.LittleEndian.PutUint32(initPayload[4:8], 38)
	if _, errno, _ := proxyRequest(t, proxy,
		[][]byte{fuseInHeader(fuseInit, 1, 0, len(initPayload)), initPayload}, 16, 64); errno != 0 {
		t.Fatalf("FUSE_INIT errno %d", errno)
	}
	prepared, _, err := hub.Prepare("docs", root, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hub.Publish(prepared); err != nil {
		t.Fatal(err)
	}

	lookup := func(unique, parent uint64, name string) (uint64, int32) {
		wireName := append([]byte(name), 0)
		_, errno, out := proxyRequest(t, proxy,
			[][]byte{fuseInHeader(fuseLookup, unique, parent, len(wireName)), wireName}, 16, 128)
		if errno != 0 {
			return 0, errno
		}
		return binary.LittleEndian.Uint64(out[1][0:8]), 0
	}
	tagNode, errno := lookup(2, 1, "docs")
	if errno != 0 {
		t.Fatalf("share lookup errno %d", errno)
	}
	fileNode, errno := lookup(3, tagNode, "hello.txt")
	if errno != 0 {
		t.Fatalf("file lookup errno %d", errno)
	}
	openIn := make([]byte, 8)
	_, errno, openOut := proxyRequest(t, proxy,
		[][]byte{fuseInHeader(fuseOpen, 4, fileNode, len(openIn)), openIn}, 16, 16)
	if errno != 0 {
		t.Fatalf("read open errno %d", errno)
	}
	readIn := make([]byte, 40)
	copy(readIn[0:8], openOut[1][0:8])
	binary.LittleEndian.PutUint32(readIn[16:20], 4096)
	_, errno, readOut := proxyRequest(t, proxy,
		[][]byte{fuseInHeader(15 /* FUSE_READ */, 5, fileNode, len(readIn)), readIn}, 16, 4096)
	if errno != 0 || string(readOut[1][:9]) != "brokered\n" {
		t.Fatalf("brokered read errno=%d payload=%q", errno, readOut[1][:9])
	}
	reporter, ok := hub.handler.(interface {
		GantryResourceUsage() (nodes, handles int)
	})
	if !ok {
		t.Fatal("real go-fuse handler does not expose broker resource accounting")
	}
	if nodes, handles := reporter.GantryResourceUsage(); nodes < 3 || handles != 1 {
		t.Fatalf("live broker resources after open = nodes %d handles %d, want >=3/1", nodes, handles)
	}
	binary.LittleEndian.PutUint32(openIn[0:4], 1) // Linux O_WRONLY on the wire.
	if _, errno, _ := proxyRequest(t, proxy,
		[][]byte{fuseInHeader(fuseOpen, 6, fileNode, len(openIn)), openIn}, 16, 16); errno != -30 {
		t.Fatalf("writable open on RO broker export errno %d, want EROFS", errno)
	}
	releaseIn := make([]byte, 24)
	copy(releaseIn[0:8], openOut[1][0:8])
	if n, errno, _ := proxyRequest(t, proxy,
		[][]byte{fuseInHeader(fuse.OpRelease, 7, fileNode, len(releaseIn)), releaseIn}, 16); n != 16 || errno != 0 {
		t.Fatalf("brokered FUSE_RELEASE = n %d errno %d, want 16/0", n, errno)
	}
	if _, handles := reporter.GantryResourceUsage(); handles != 0 {
		t.Fatalf("live broker handles after release = %d, want 0", handles)
	}
	forgetIn := make([]byte, 8)
	binary.LittleEndian.PutUint64(forgetIn, 1)
	if n, errno, _ := proxyRequest(t, proxy,
		[][]byte{fuseInHeader(2 /* FUSE_FORGET */, 0, fileNode, len(forgetIn)), forgetIn}); n != 0 || errno != 0 {
		t.Fatalf("brokered FUSE_FORGET = n %d errno %d, want 0/0", n, errno)
	}

	if err := proxy.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-serveErr; err != nil {
		t.Fatalf("ServeBroker after peer close: %v", err)
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

func TestShareHubProxyRejectsOversizedRequestBeforeWrite(t *testing.T) {
	stream := &brokerSpyRWC{}
	proxy, err := NewShareHubProxy(stream)
	if err != nil {
		t.Fatal(err)
	}
	n, status := proxy.handler.HandleRequest(
		[][]byte{make([]byte, fsMaxChainBytes)},
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

func TestShareHubProxyFrontendDoesNotOwnTransport(t *testing.T) {
	stream := &brokerSpyRWC{}
	proxy, err := NewShareHubProxy(stream)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := proxy.VirtioDevice().(io.Closer); ok {
		t.Fatal("virtio frontend unexpectedly owns the broker transport")
	}
	if stream.closed {
		t.Fatal("constructing the frontend closed the broker transport")
	}
	if err := proxy.Close(); err != nil {
		t.Fatal(err)
	}
	if !stream.closed {
		t.Fatal("owning proxy Close did not close the broker transport")
	}
}

func TestShareHubBrokerRejectsMalformedCounts(t *testing.T) {
	hub := testBrokerHub(&brokerTestHandler{})
	server, client := net.Pipe()
	serveErr := make(chan error, 1)
	go func() { serveErr <- hub.ServeBroker(server) }()

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

func TestShareHubBrokerRejectsTruncatedInput(t *testing.T) {
	hub := testBrokerHub(&brokerTestHandler{})
	server, client := net.Pipe()
	serveErr := make(chan error, 1)
	go func() { serveErr <- hub.ServeBroker(server) }()

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

func TestShareHubProxyRejectsWrongResponseID(t *testing.T) {
	server, client := net.Pipe()
	serverErr := make(chan error, 1)
	go func() {
		var hdr [shareBrokerHeaderSize]byte
		if _, err := io.ReadFull(server, hdr[:]); err != nil {
			serverErr <- err
			return
		}
		_, inLens, _, err := readShareBrokerRequest(server, hdr[:], 0)
		if err == nil {
			_, err = readBrokerInput(server, inLens)
		}
		if err == nil {
			err = writeShareBrokerResponse(server, 2, fuse.OK, nil)
		}
		serverErr <- err
	}()
	proxy, err := NewShareHubProxy(client)
	if err != nil {
		t.Fatal(err)
	}
	if n, status := proxy.handler.HandleRequest([][]byte{{1}}, nil); n != 0 || status != fuse.EIO {
		t.Fatalf("wrong response ID = n %d status %v, want 0/EIO", n, status)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
	_ = proxy.Close()
	_ = server.Close()
}

func TestShareHubBrokerContainsHandlerPanic(t *testing.T) {
	hub := testBrokerHub(&brokerTestHandler{panicOn: 0xff})
	server, client := net.Pipe()
	serveErr := make(chan error, 1)
	go func() { serveErr <- hub.ServeBroker(server) }()
	proxy, err := NewShareHubProxy(client)
	if err != nil {
		t.Fatal(err)
	}

	n, status := proxy.handler.HandleRequest([][]byte{{0xff}}, [][]byte{make([]byte, 16)})
	if n != 0 || status != fuse.EIO {
		t.Fatalf("panic request = n %d status %v, want 0/EIO", n, status)
	}
	if err := <-serveErr; err == nil || !strings.Contains(err.Error(), "FUSE handler panic") {
		t.Fatalf("ServeBroker error = %v, want contained panic", err)
	}
	_ = proxy.Close()
}

func TestShareHubBrokerFailsClosedOnRetainedResourceLimit(t *testing.T) {
	for _, tc := range []struct {
		name    string
		nodes   int
		handles int
		want    string
	}{
		{name: "handles", handles: shareBrokerHandleLimit() + 1, want: "live handle limit"},
		{name: "inodes", nodes: shareBrokerMaxLiveNodes + 1, want: "live inode limit"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			handler := &brokerResourceHandler{nodes: tc.nodes, handles: tc.handles}
			hub := testBrokerHub(handler)
			server, client := net.Pipe()
			serveErr := make(chan error, 1)
			go func() { serveErr <- hub.ServeBroker(server) }()
			proxy, err := NewShareHubProxy(client)
			if err != nil {
				t.Fatal(err)
			}

			if n, status := proxy.handler.HandleRequest([][]byte{{1}}, [][]byte{make([]byte, 8)}); n != 0 || status != fuse.EIO {
				t.Fatalf("quota request = n %d status %v, want 0/EIO", n, status)
			}
			if err := <-serveErr; err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ServeBroker quota error = %v, want %q", err, tc.want)
			}
			_ = proxy.Close()
		})
	}
}
