package workerproto

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestMessageRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	in := Handshake{Magic: Magic, Role: RoleNet, Nonce: "ab", Config: json.RawMessage(`{"x":1}`)}
	if err := WriteMessage(&buf, in); err != nil {
		t.Fatal(err)
	}
	var out Handshake
	if err := ReadMessage(&buf, &out); err != nil {
		t.Fatal(err)
	}
	if out.Magic != Magic || out.Role != RoleNet || string(out.Config) != `{"x":1}` {
		t.Fatalf("round trip mismatch: %+v", out)
	}
}

func TestMessageLengthBounds(t *testing.T) {
	// zero length
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.BigEndian, uint32(0))
	if err := ReadMessage(&buf, &struct{}{}); err == nil {
		t.Fatal("zero-length message accepted")
	}
	// oversized length prefix must fail BEFORE any large allocation
	buf.Reset()
	_ = binary.Write(&buf, binary.BigEndian, uint32(MaxMessage+1))
	if err := ReadMessage(&buf, &struct{}{}); err == nil {
		t.Fatal("oversized message accepted")
	}
	// exactly at the cap with valid JSON is fine
	buf.Reset()
	payload := []byte(strings.Repeat(" ", MaxMessage-2))
	payload[0], payload[len(payload)-1] = '[', ']'
	_ = binary.Write(&buf, binary.BigEndian, uint32(len(payload)))
	buf.Write(payload)
	var arr []json.RawMessage
	if err := ReadMessage(&buf, &arr); err != nil {
		t.Fatalf("cap-sized message rejected: %v", err)
	}
}

func TestFrameBounds(t *testing.T) {
	buf := make([]byte, MaxFrame)
	// zero-length frame
	var w bytes.Buffer
	_ = binary.Write(&w, binary.BigEndian, uint32(0))
	if _, err := ReadFrame(&w, buf); err == nil {
		t.Fatal("zero-length frame accepted")
	}
	// oversized declared length: fail without allocating
	w.Reset()
	_ = binary.Write(&w, binary.BigEndian, uint32(MaxFrame+1))
	if _, err := ReadFrame(&w, buf); err == nil {
		t.Fatal("oversized frame accepted")
	}
	// truncated frame body
	w.Reset()
	_ = binary.Write(&w, binary.BigEndian, uint32(60))
	w.Write(make([]byte, 30))
	if _, err := ReadFrame(&w, buf); err == nil {
		t.Fatal("truncated frame accepted")
	}
	// valid frame round trip
	w.Reset()
	frame := bytes.Repeat([]byte{0xab}, 60)
	if err := WriteFrame(&w, frame); err != nil {
		t.Fatal(err)
	}
	n, err := ReadFrame(&w, buf)
	if err != nil || n != 60 || !bytes.Equal(buf[:n], frame) {
		t.Fatalf("frame round trip: n=%d err=%v", n, err)
	}
	// writer side refuses out-of-bounds frames
	if err := WriteFrame(io.Discard, nil); err == nil {
		t.Fatal("nil frame written")
	}
	if err := WriteFrame(io.Discard, make([]byte, MaxFrame+1)); err == nil {
		t.Fatal("oversized frame written")
	}
}

func TestNonceCrossCheck(t *testing.T) {
	nonce := NewNonce()
	var buf bytes.Buffer
	if err := WriteNonce(&buf, nonce); err != nil {
		t.Fatal(err)
	}
	if err := ReadNonce(&buf, nonce); err != nil {
		t.Fatal(err)
	}
	other := NewNonce()
	if err := ReadNonce(bytes.NewReader(buf.Bytes()), other); err == nil {
		t.Fatal("nonce mismatch not detected")
	}
	if err := ReadNonce(bytes.NewReader(buf.Bytes()[:10]), nonce); err == nil {
		t.Fatal("short nonce accepted")
	}
}

func handshakePair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	return a, b
}

func TestHandshakeValidation(t *testing.T) {
	type cfg struct {
		X int `json:"x"`
	}
	good := func() (net.Conn, chan error) {
		c, s := handshakePair(t)
		done := make(chan error, 1)
		go func() {
			var got cfg
			_, err := ServeHandshake(s, RoleNet, &got)
			if err == nil && got.X != 42 {
				err = io.ErrUnexpectedEOF
			}
			done <- err
		}()
		return c, done
	}

	c, done := good()
	if err := SendHandshake(c, RoleNet, NewNonce(), cfg{X: 42}); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("valid handshake rejected: %v", err)
	}

	c, done = good()
	_ = WriteMessage(c, Handshake{Magic: "GANTRY-WORKER/0", Role: RoleNet, Nonce: "00"})
	if err := <-done; err == nil {
		t.Fatal("bad magic accepted")
	}

	c, done = good()
	_ = WriteMessage(c, Handshake{Magic: Magic, Role: "vmm", Nonce: "00"})
	if err := <-done; err == nil {
		t.Fatal("wrong role accepted")
	}

	c, done = good()
	_ = WriteMessage(c, Handshake{Magic: Magic, Role: RoleNet, Nonce: "zz"})
	if err := <-done; err == nil {
		t.Fatal("malformed nonce accepted")
	}

	c, done = good()
	_ = WriteMessage(c, Handshake{Magic: Magic, Role: RoleNet, Nonce: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"})
	if err := <-done; err == nil {
		t.Fatal("missing config accepted")
	}
}

func TestServeRequestsProtocolErrors(t *testing.T) {
	serve := func(t *testing.T, writes func(c net.Conn)) error {
		c, s := handshakePair(t)
		done := make(chan error, 1)
		go func() {
			done <- ServeRequests(s, map[string]Handler{
				"ok": func(req Request) (any, error) { return nil, nil },
			})
		}()
		writes(c)
		select {
		case err := <-done:
			return err
		case <-time.After(5 * time.Second):
			t.Fatal("ServeRequests hung")
			return nil
		}
	}

	// unknown op is fatal
	if err := serve(t, func(c net.Conn) {
		_ = WriteMessage(c, Request{ID: 1, Op: "bogus"})
	}); err == nil {
		t.Fatal("unknown op not fatal")
	}
	// duplicate ID is fatal
	if err := serve(t, func(c net.Conn) {
		_ = WriteMessage(c, Request{ID: 1, Op: "ok"})
		var resp Response
		_ = ReadMessage(c, &resp)
		_ = WriteMessage(c, Request{ID: 1, Op: "ok"})
	}); err == nil {
		t.Fatal("duplicate ID not fatal")
	}
	// out-of-order ID is fatal
	if err := serve(t, func(c net.Conn) {
		_ = WriteMessage(c, Request{ID: 7, Op: "ok"})
		var resp Response
		_ = ReadMessage(c, &resp)
		_ = WriteMessage(c, Request{ID: 3, Op: "ok"})
	}); err == nil {
		t.Fatal("out-of-order ID not fatal")
	}
	// clean EOF is a graceful shutdown, not an error
	if err := serve(t, func(c net.Conn) {
		_ = c.Close()
	}); err != nil {
		t.Fatalf("clean EOF: %v", err)
	}
	// malformed JSON is fatal
	if err := serve(t, func(c net.Conn) {
		var hdr [4]byte
		binary.BigEndian.PutUint32(hdr[:], 5)
		_, _ = c.Write(append(hdr[:], []byte("{junk")...))
	}); err == nil {
		t.Fatal("malformed JSON not fatal")
	}
}

func TestServeRequestsBoundsConcurrentHandlers(t *testing.T) {
	c, s := handshakePair(t)
	release := make(chan struct{})
	started := make(chan struct{}, MaxConcurrentHandlers+1)
	var active, peak atomic.Int64
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- ServeRequests(s, map[string]Handler{
			"park": func(Request) (any, error) {
				n := active.Add(1)
				for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
				}
				started <- struct{}{}
				<-release
				active.Add(-1)
				return nil, nil
			},
		})
	}()
	cl := NewClient(c)
	callErr := make(chan error, MaxConcurrentHandlers+1)
	for i := 0; i < MaxConcurrentHandlers+1; i++ {
		go func() { callErr <- cl.CallContext(context.Background(), "park", nil, nil) }()
	}
	for i := 0; i < MaxConcurrentHandlers; i++ {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatalf("only %d/%d handlers started", i, MaxConcurrentHandlers)
		}
	}
	select {
	case <-started:
		t.Fatalf("more than %d handlers ran concurrently", MaxConcurrentHandlers)
	case <-time.After(50 * time.Millisecond):
	}
	// Releasing one slot admits exactly the backpressured request.
	release <- struct{}{}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("backpressured request was not admitted after a slot released")
	}
	close(release)
	for i := 0; i < MaxConcurrentHandlers+1; i++ {
		select {
		case err := <-callErr:
			if err != nil {
				t.Fatalf("call %d: %v", i, err)
			}
		case <-time.After(time.Second):
			t.Fatalf("call %d did not finish", i)
		}
	}
	if got := peak.Load(); got > MaxConcurrentHandlers {
		t.Fatalf("peak concurrent handlers = %d, cap %d", got, MaxConcurrentHandlers)
	}
	_ = cl.Close()
	select {
	case err := <-serveErr:
		if err != nil {
			t.Fatalf("ServeRequests: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("ServeRequests did not stop after client close")
	}
}

func TestServeRequestsOrderedOpsPreserveWireOrder(t *testing.T) {
	c, s := handshakePair(t)
	firstStarted := make(chan struct{})
	secondStarted := make(chan struct{})
	freeStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- ServeRequestsWithOptions(s, map[string]Handler{
			"ordered": func(req Request) (any, error) {
				switch req.ID {
				case 1:
					close(firstStarted)
					<-releaseFirst
				case 2:
					close(secondStarted)
				}
				return nil, nil
			},
			"free": func(Request) (any, error) {
				close(freeStarted)
				return nil, nil
			},
		}, ServeOptions{OrderedOps: map[string]bool{"ordered": true}})
	}()
	responses := make(chan Response, 3)
	readErr := make(chan error, 1)
	go func() {
		for i := 0; i < 3; i++ {
			var resp Response
			if err := ReadMessage(c, &resp); err != nil {
				readErr <- err
				return
			}
			responses <- resp
		}
	}()
	if err := WriteMessage(c, Request{ID: 1, Op: "ordered"}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-firstStarted:
	case <-time.After(time.Second):
		t.Fatal("first ordered handler did not start")
	}
	if err := WriteMessage(c, Request{ID: 2, Op: "ordered"}); err != nil {
		t.Fatal(err)
	}
	if err := WriteMessage(c, Request{ID: 3, Op: "free"}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-freeStarted:
	case <-time.After(time.Second):
		t.Fatal("unordered handler was starved behind an ordered handler")
	}
	select {
	case <-secondStarted:
		t.Fatal("second ordered handler overtook the first")
	case <-time.After(50 * time.Millisecond):
	}
	close(releaseFirst)
	select {
	case <-secondStarted:
	case <-time.After(time.Second):
		t.Fatal("second ordered handler did not start after the first completed")
	}
	for i := 0; i < 3; i++ {
		select {
		case resp := <-responses:
			if !resp.OK {
				t.Fatalf("response %d: %+v", i, resp)
			}
		case err := <-readErr:
			t.Fatalf("read response: %v", err)
		case <-time.After(time.Second):
			t.Fatalf("response %d did not arrive", i)
		}
	}
	_ = c.Close()
	select {
	case err := <-serveErr:
		if err != nil {
			t.Fatalf("ServeRequestsWithOptions: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("ServeRequestsWithOptions did not stop after client close")
	}
}

func TestClientCallRoundTrip(t *testing.T) {
	c, s := handshakePair(t)
	go func() {
		_ = ServeRequests(s, map[string]Handler{
			"echo": func(req Request) (any, error) {
				var v string
				if err := DecodeBody(req, &v); err != nil {
					return nil, err
				}
				return map[string]string{"got": v}, nil
			},
		})
	}()
	cl := NewClient(c)
	cl.Timeout = 2 * time.Second
	var out struct {
		Got string `json:"got"`
	}
	if err := cl.Call("echo", "hello", &out); err != nil || out.Got != "hello" {
		t.Fatalf("call: %v out=%+v", err, out)
	}
	// unknown op is fatal to the worker; process exit would close the
	// conn, surfacing EOF to the in-flight call
	if err := cl.Call("nope", nil, nil); err == nil {
		t.Fatal("unknown op call succeeded")
	}
	_ = s.Close()
	if err := cl.Call("echo", "x", nil); err == nil {
		t.Fatal("call on dead worker succeeded")
	}
}

func TestClientCallContextHasNoImplicitTimeout(t *testing.T) {
	c, s := handshakePair(t)
	started := make(chan struct{})
	release := make(chan struct{})
	go func() {
		_ = ServeRequests(s, map[string]Handler{
			"park": func(Request) (any, error) {
				close(started)
				<-release
				return nil, nil
			},
		})
	}()
	cl := NewClient(c)
	cl.Timeout = 5 * time.Millisecond
	done := make(chan error, 1)
	go func() { done <- cl.CallContext(context.Background(), "park", nil, nil) }()

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("park request did not reach the server")
	}
	select {
	case err := <-done:
		t.Fatalf("unbounded context call inherited the client timeout: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("CallContext: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("CallContext did not receive the released response")
	}
}

func TestClientCallContextCancellationDropsLateResponse(t *testing.T) {
	c, s := handshakePair(t)
	started := make(chan struct{})
	release := make(chan struct{})
	go func() {
		_ = ServeRequests(s, map[string]Handler{
			"park": func(Request) (any, error) {
				close(started)
				<-release
				return nil, nil
			},
			"ping": func(Request) (any, error) { return "pong", nil },
		})
	}()
	cl := NewClient(c)
	cl.Timeout = time.Second
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- cl.CallContext(ctx, "park", nil, nil) }()

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("park request did not reach the server")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled call = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled call remained parked")
	}

	// The abandoned response is stale, not a protocol error. The same
	// control channel must remain usable for later operations.
	close(release)
	var out string
	if err := cl.Call("ping", nil, &out); err != nil || out != "pong" {
		t.Fatalf("call after late response: err=%v out=%q", err, out)
	}
}

func TestClientCallContextControlDeath(t *testing.T) {
	c, s := handshakePair(t)
	received := make(chan struct{})
	go func() {
		var req Request
		_ = ReadMessage(s, &req)
		close(received)
		_ = s.Close()
	}()
	cl := NewClient(c)
	done := make(chan error, 1)
	go func() { done <- cl.CallContext(context.Background(), "park", nil, nil) }()
	select {
	case <-received:
	case <-time.After(time.Second):
		t.Fatal("request did not reach the server")
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("control death completed an outstanding call successfully")
		}
	case <-time.After(time.Second):
		t.Fatal("control death did not fail the outstanding call")
	}
}

func TestResponseIDMismatch(t *testing.T) {
	c, s := handshakePair(t)
	go func() {
		var req Request
		_ = ReadMessage(s, &req)
		_ = WriteMessage(s, Response{ID: req.ID + 99, OK: true})
	}()
	cl := NewClient(c)
	if err := cl.Call("x", nil, nil); err == nil {
		t.Fatal("mismatched response ID accepted")
	}
}

func TestShutdownOpRespondsThenReturns(t *testing.T) {
	c, s := handshakePair(t)
	done := make(chan error, 1)
	go func() {
		done <- ServeRequests(s, map[string]Handler{
			"shutdown": func(Request) (any, error) {
				return map[string]string{"final": "state"}, ErrShutdown
			},
		})
	}()
	cl := NewClient(c)
	var out map[string]string
	if err := cl.Call("shutdown", nil, &out); err != nil {
		t.Fatalf("shutdown call: %v", err)
	}
	if out["final"] != "state" {
		t.Fatalf("shutdown response = %v, want final state", out)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ServeRequests after shutdown: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ServeRequests did not return after shutdown")
	}
}
