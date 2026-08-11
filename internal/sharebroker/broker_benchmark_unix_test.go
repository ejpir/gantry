//go:build linux || darwin

package sharebroker

import (
	"net"
	"os"
	"syscall"
	"testing"

	"github.com/ejpir/gantry/internal/fusewire"

	"github.com/hanwen/go-fuse/v2/fuse"
)

type roundTripBenchmarkHandler struct{ responseBytes int }

func (h roundTripBenchmarkHandler) HandleRequest(_ [][]byte, out [][]byte) (int, fuse.Status) {
	remaining := h.responseBytes
	for _, part := range out {
		if remaining == 0 {
			break
		}
		n := min(len(part), remaining)
		if n != 0 {
			part[0] = 1
		}
		remaining -= n
	}
	if remaining != 0 {
		return 0, fuse.EIO
	}
	return h.responseBytes, fuse.OK
}

func benchmarkSocketPair(b *testing.B) (net.Conn, net.Conn) {
	b.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		b.Fatal(err)
	}
	makeConn := func(fd int, name string) net.Conn {
		file := os.NewFile(uintptr(fd), name)
		conn, err := net.FileConn(file)
		_ = file.Close()
		if err != nil {
			b.Fatal(err)
		}
		return conn
	}
	return makeConn(fds[0], "broker-benchmark-server"), makeConn(fds[1], "broker-benchmark-client")
}

func benchmarkRoundTrip(b *testing.B, payloadBytes int) {
	b.Helper()
	responseBytes := 16 + payloadBytes
	server, transport := benchmarkSocketPair(b)
	serveErr := make(chan error, 1)
	go func() { serveErr <- Serve(server, roundTripBenchmarkHandler{responseBytes: responseBytes}) }()
	client, err := NewClient(transport)
	if err != nil {
		b.Fatal(err)
	}
	in := [][]byte{make([]byte, fusewire.InHeaderSize)}
	out := [][]byte{make([]byte, 16), make([]byte, payloadBytes)}

	b.ReportAllocs()
	b.SetBytes(int64(responseBytes))
	b.ResetTimer()
	for b.Loop() {
		if n, status := client.HandleRequest(in, out); n != responseBytes || status != fuse.OK {
			b.Fatalf("round trip = %d/%v, want %d/OK", n, status, responseBytes)
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

func BenchmarkMetadataRoundTrip(b *testing.B) { benchmarkRoundTrip(b, 0) }

func BenchmarkRead128KiBRoundTrip(b *testing.B) { benchmarkRoundTrip(b, 128<<10) }
