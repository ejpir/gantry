package workerproto

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

type shortWriter struct{}

func (shortWriter) Write(payload []byte) (int, error) {
	if len(payload) == 0 {
		return 0, nil
	}
	return len(payload) - 1, nil
}

func TestFramedWritesRejectShortWrite(t *testing.T) {
	nonce := make([]byte, nonceLen)
	tests := []struct {
		name  string
		write func() error
	}{
		{name: "message", write: func() error { return WriteMessage(shortWriter{}, Request{ID: 1, Op: "ping"}) }},
		{name: "frame", write: func() error { return WriteFrame(shortWriter{}, []byte{1}) }},
		{name: "reusable frame", write: func() error {
			var writer FrameWriter
			return writer.WriteFrame(shortWriter{}, []byte{1})
		}},
		{name: "nonce", write: func() error { return WriteNonce(shortWriter{}, nonce) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.write(); !errors.Is(err, io.ErrShortWrite) {
				t.Fatalf("write error = %v, want io.ErrShortWrite", err)
			}
		})
	}
}

func TestServeRequestsTreatsTruncatedMessageAsError(t *testing.T) {
	client, server := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- ServeRequests(server, map[string]Handler{}) }()
	if _, err := client.Write([]byte{0, 0}); err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	select {
	case err := <-done:
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("ServeRequests error = %v, want io.ErrUnexpectedEOF", err)
		}
	case <-time.After(time.Second):
		t.Fatal("ServeRequests did not stop after truncated input")
	}
}

func TestServeRequestsCancelsQueuedHandlersOnProtocolFailure(t *testing.T) {
	client, server := net.Pipe()
	firstStarted := make(chan struct{})
	firstDone := make(chan struct{})
	releaseFirst := make(chan struct{})
	secondStarted := make(chan struct{}, 1)
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- ServeRequestsWithOptions(server, map[string]Handler{
			"ordered": func(request Request) (any, error) {
				switch request.ID {
				case 1:
					close(firstStarted)
					defer close(firstDone)
					<-releaseFirst
				case 2:
					secondStarted <- struct{}{}
				}
				return nil, nil
			},
		}, ServeOptions{OrderedOps: map[string]bool{"ordered": true}})
	}()
	if err := WriteMessage(client, Request{ID: 1, Op: "ordered"}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-firstStarted:
	case <-time.After(time.Second):
		t.Fatal("first handler did not start")
	}
	if err := WriteMessage(client, Request{ID: 2, Op: "ordered"}); err != nil {
		t.Fatal(err)
	}
	if err := WriteMessage(client, Request{ID: 3, Op: "unknown"}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-serveDone:
		if err == nil {
			t.Fatal("unknown operation did not terminate the server")
		}
	case <-time.After(time.Second):
		t.Fatal("server did not terminate on unknown operation")
	}
	close(releaseFirst)
	select {
	case <-firstDone:
	case <-time.After(time.Second):
		t.Fatal("running handler did not finish after release")
	}
	select {
	case <-secondStarted:
		t.Fatal("queued handler started after the relationship terminated")
	case <-time.After(50 * time.Millisecond):
	}
}

var errTestWrite = errors.New("test write failure")

type writeFailureConn struct {
	input     *bytes.Reader
	closed    chan struct{}
	closeOnce sync.Once
}

func newWriteFailureConn(input []byte) *writeFailureConn {
	return &writeFailureConn{input: bytes.NewReader(input), closed: make(chan struct{})}
}

func (conn *writeFailureConn) Read(payload []byte) (int, error) {
	if conn.input.Len() != 0 {
		return conn.input.Read(payload)
	}
	<-conn.closed
	return 0, net.ErrClosed
}

func (*writeFailureConn) Write([]byte) (int, error) { return 0, errTestWrite }
func (conn *writeFailureConn) Close() error {
	conn.closeOnce.Do(func() { close(conn.closed) })
	return nil
}
func (*writeFailureConn) LocalAddr() net.Addr              { return testAddr("local") }
func (*writeFailureConn) RemoteAddr() net.Addr             { return testAddr("remote") }
func (*writeFailureConn) SetDeadline(time.Time) error      { return nil }
func (*writeFailureConn) SetReadDeadline(time.Time) error  { return nil }
func (*writeFailureConn) SetWriteDeadline(time.Time) error { return nil }

type testAddr string

func (address testAddr) Network() string { return string(address) }
func (address testAddr) String() string  { return string(address) }

func TestClientWriteFailureTerminatesRelationship(t *testing.T) {
	conn := newWriteFailureConn(nil)
	client := NewClient(conn)
	if err := client.CallContext(t.Context(), "ping", nil, nil); !errors.Is(err, errTestWrite) {
		t.Fatalf("first call error = %v, want write failure", err)
	}
	select {
	case <-conn.closed:
	default:
		t.Fatal("write failure did not close the connection")
	}
	if err := client.CallContext(t.Context(), "ping", nil, nil); !errors.Is(err, errTestWrite) {
		t.Fatalf("call after failure = %v, want sticky write failure", err)
	}
}

func TestServerWriteFailureTerminatesRelationship(t *testing.T) {
	var input bytes.Buffer
	if err := WriteMessage(&input, Request{ID: 1, Op: "ping"}); err != nil {
		t.Fatal(err)
	}
	conn := newWriteFailureConn(input.Bytes())
	err := ServeRequests(conn, map[string]Handler{
		"ping": func(Request) (any, error) { return "pong", nil },
	})
	if !errors.Is(err, errTestWrite) {
		t.Fatalf("ServeRequests error = %v, want write failure", err)
	}
	select {
	case <-conn.closed:
	default:
		t.Fatal("write failure did not close the connection")
	}
}

func BenchmarkMessageWriter(b *testing.B) {
	request := Request{ID: 42, Op: "policy.status", Body: []byte(`{"generation":7}`)}
	var writer messageWriter
	b.ReportAllocs()
	for b.Loop() {
		if err := writer.writeMessage(io.Discard, request); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMessageReader(b *testing.B) {
	var framed bytes.Buffer
	if err := WriteMessage(&framed, Request{ID: 42, Op: "policy.status", Body: []byte(`{"generation":7}`)}); err != nil {
		b.Fatal(err)
	}
	payload := framed.Bytes()
	var input bytes.Reader
	var reader messageReader
	b.ReportAllocs()
	for b.Loop() {
		input.Reset(payload)
		var request Request
		if err := reader.readMessage(&input, &request); err != nil {
			b.Fatal(err)
		}
	}
}
