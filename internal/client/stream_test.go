package client

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

type streamTestConn struct {
	ack        bytes.Reader
	written    bytes.Buffer
	writes     int
	shortWrite bool
	closed     bool
}

func streamAck(value string) []byte {
	packet := make([]byte, 4+len(value))
	binary.BigEndian.PutUint32(packet[:4], uint32(len(value)))
	copy(packet[4:], value)
	return packet
}

func (conn *streamTestConn) resetAck(packet []byte) {
	conn.ack.Reset(packet)
	conn.written.Reset()
	conn.writes = 0
	conn.closed = false
}

func (conn *streamTestConn) Read(payload []byte) (int, error) { return conn.ack.Read(payload) }
func (conn *streamTestConn) Write(payload []byte) (int, error) {
	conn.writes++
	if conn.shortWrite {
		return len(payload) - 1, nil
	}
	return conn.written.Write(payload)
}
func (conn *streamTestConn) Close() error                { conn.closed = true; return nil }
func (*streamTestConn) LocalAddr() net.Addr              { return streamTestAddr("local") }
func (*streamTestConn) RemoteAddr() net.Addr             { return streamTestAddr("remote") }
func (*streamTestConn) SetDeadline(time.Time) error      { return nil }
func (*streamTestConn) SetReadDeadline(time.Time) error  { return nil }
func (*streamTestConn) SetWriteDeadline(time.Time) error { return nil }

type streamTestAddr string

func (address streamTestAddr) Network() string { return string(address) }
func (address streamTestAddr) String() string  { return string(address) }

func TestClaimStreamRoundTripUsesOneWrite(t *testing.T) {
	const id = "stdin-abcdef"
	conn := &streamTestConn{}
	conn.resetAck(streamAck(id))
	if err := claimStream(conn, id); err != nil {
		t.Fatal(err)
	}
	if conn.writes != 1 {
		t.Fatalf("handshake writes = %d, want one", conn.writes)
	}
	request := conn.written.Bytes()
	if len(request) != 4+len(id) || binary.BigEndian.Uint32(request[:4]) != uint32(len(id)) || string(request[4:]) != id {
		t.Fatalf("request = %x", request)
	}
}

func TestDialStreamRejectsBoundedProtocolFailures(t *testing.T) {
	t.Run("short write", func(t *testing.T) {
		conn := &streamTestConn{shortWrite: true}
		result, err := dialStream(func() (net.Conn, error) { return conn, nil }, "stdin-abcdef")
		if result != nil || !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("dialStream = (%v, %v), want short write", result, err)
		}
		if !conn.closed {
			t.Fatal("short write did not close the stream")
		}
	})

	t.Run("oversized acknowledgement", func(t *testing.T) {
		var header [4]byte
		binary.BigEndian.PutUint32(header[:], maxStreamHandshakeString+1)
		conn := &streamTestConn{}
		conn.ack.Reset(header[:])
		result, err := dialStream(func() (net.Conn, error) { return conn, nil }, "stdin-abcdef")
		if result != nil || err == nil {
			t.Fatalf("dialStream = (%v, %v), want bounded acknowledgement error", result, err)
		}
		if !conn.closed {
			t.Fatal("invalid acknowledgement did not close the stream")
		}
	})
}

func TestClaimStreamTimesOutWhenPeerWithholdsAck(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()
	requestRead := make(chan struct{})
	releasePeer := make(chan struct{})
	defer close(releasePeer)
	go func() {
		var size [4]byte
		if _, err := io.ReadFull(server, size[:]); err != nil {
			close(requestRead)
			return
		}
		payload := make([]byte, binary.BigEndian.Uint32(size[:]))
		_, _ = io.ReadFull(server, payload)
		close(requestRead)
		// Keep the relationship open without acknowledging it.
		<-releasePeer
	}()
	start := time.Now()
	err := claimStreamWithTimeout(client, "stdin-stalled", 20*time.Millisecond)
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("claimStream error = %v, want deadline", err)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("claimStream timeout took %v", elapsed)
	}
	<-requestRead
}

func BenchmarkClaimStream(b *testing.B) {
	const id = "stdout-abcdef"
	ack := streamAck(id)
	conn := &streamTestConn{}
	conn.written.Grow(4 + len(id))
	b.ReportAllocs()
	for b.Loop() {
		conn.resetAck(ack)
		if err := claimStream(conn, id); err != nil {
			b.Fatal(err)
		}
	}
}
