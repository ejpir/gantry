package diskbroker

import (
	"bytes"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestClientServeReadWriteSync(t *testing.T) {
	const size = 2 << 20
	path := filepath.Join(t.TempDir(), "disk.img")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(size); err != nil {
		t.Fatal(err)
	}
	server, transport := net.Pipe()
	serveErr := make(chan error, 1)
	go func() { serveErr <- Serve(server, file, size) }()
	client, err := NewClient(transport, "test", size)
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("gantry"), 1024)
	if n, err := client.WriteAt(payload, 4096); err != nil || n != len(payload) {
		t.Fatalf("WriteAt = %d, %v", n, err)
	}
	got := make([]byte, len(payload))
	if n, err := client.ReadAt(got, 4096); err != nil || n != len(got) {
		t.Fatalf("ReadAt = %d, %v", n, err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("brokered disk read did not return written data")
	}
	if err := client.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-serveErr; err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(path); err != nil || info.Size() != size {
		t.Fatalf("disk stat = %+v, %v", info, err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestClientRejectsOutOfBoundsBeforeTransportWrite(t *testing.T) {
	stream := &countingConn{}
	client, err := NewClient(stream, "bounded", 4096)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.WriteAt([]byte{1, 2}, 4095); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("out-of-bounds write error = %v", err)
	}
	if stream.writes != 0 {
		t.Fatalf("out-of-bounds write sent %d bytes", stream.writes)
	}
}

func TestServerRejectsForgedOutOfBoundsWriteWithoutGrowingDisk(t *testing.T) {
	const size = int64(4096)
	path := filepath.Join(t.TempDir(), "disk.img")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(size); err != nil {
		t.Fatal(err)
	}
	server, peer := net.Pipe()
	serveErr := make(chan error, 1)
	go func() { serveErr <- Serve(server, file, uint64(size)) }()
	var header [headerSize]byte
	putHeader(header[:], opWrite, 1, uint64(size-1), 2, statusOK)
	if err := writeAll(peer, header[:]); err != nil {
		t.Fatal(err)
	}
	if err := writeAll(peer, []byte{1, 2}); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(peer, header[:]); err != nil {
		t.Fatal(err)
	}
	_, _, _, _, status, err := parseHeader(header[:])
	if err != nil || status != statusInvalid {
		t.Fatalf("forged response status = %d, %v", status, err)
	}
	_ = peer.Close()
	if err := <-serveErr; err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(path); err != nil || info.Size() != size {
		t.Fatalf("forged write changed disk size: %+v, %v", info, err)
	}
	_ = file.Close()
}

type countingConn struct {
	writes int
}

func (conn *countingConn) Read([]byte) (int, error) { return 0, io.EOF }
func (conn *countingConn) Write(buffer []byte) (int, error) {
	conn.writes += len(buffer)
	return len(buffer), nil
}
func (conn *countingConn) Close() error                     { return nil }
func (conn *countingConn) LocalAddr() net.Addr              { return dummyAddr("local") }
func (conn *countingConn) RemoteAddr() net.Addr             { return dummyAddr("remote") }
func (conn *countingConn) SetDeadline(time.Time) error      { return nil }
func (conn *countingConn) SetReadDeadline(time.Time) error  { return nil }
func (conn *countingConn) SetWriteDeadline(time.Time) error { return nil }

type dummyAddr string

func (addr dummyAddr) Network() string { return string(addr) }
func (addr dummyAddr) String() string  { return string(addr) }
