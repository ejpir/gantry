//go:build unix

package vhostuser

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

func TestOneRequestRejectsTruncatedHeader(t *testing.T) {
	server, peer := newSecurityServer(t)

	if _, err := peer.Write(controlHeader(REQ_SET_OWNER, 1, 0)[:4]); err != nil {
		t.Fatal(err)
	}
	if err := peer.CloseWrite(); err != nil {
		t.Fatal(err)
	}

	if err := server.oneRequest(); err == nil {
		t.Fatal("truncated header was accepted")
	}
}

func TestOneRequestRejectsWrongPayloadSize(t *testing.T) {
	server, peer := newSecurityServer(t)

	writeAll(t, peer, controlHeader(REQ_SET_FEATURES, 1, 0))
	if err := server.oneRequest(); err == nil {
		t.Fatal("SET_FEATURES without its payload was accepted")
	}
}

func TestOneRequestRejectsInvalidFlags(t *testing.T) {
	for _, flags := range []uint32{0, 2, _VERSION | _REPLY, _VERSION | 0x10} {
		t.Run(fmt.Sprintf("%#x", flags), func(t *testing.T) {
			server, peer := newSecurityServer(t)
			writeAll(t, peer, controlHeader(REQ_SET_OWNER, flags, 0))
			if err := server.oneRequest(); err == nil {
				t.Fatalf("flags %#x were accepted", flags)
			}
		})
	}
}

func TestOneRequestAcceptsFragmentedMessage(t *testing.T) {
	server, peer := newSecurityServer(t)
	header := controlHeader(REQ_SET_FEATURES, _VERSION|_NEED_REPLY, 8)
	writeAll(t, peer, header[:1])
	done := make(chan error, 1)
	go func() { done <- server.oneRequest() }()
	select {
	case err := <-done:
		t.Fatalf("server returned after a partial header: %v", err)
	case <-time.After(10 * time.Millisecond):
	}
	writeAll(t, peer, header[1:])
	payload := make([]byte, 8)
	writeAll(t, peer, payload[:3])
	writeAll(t, peer, payload[3:])
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("fragmented request did not complete")
	}
}

func TestOneRequestClosesUnexpectedHeaderFD(t *testing.T) {
	server, peer := newSecurityServer(t)
	readEnd, writeEnd, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		readEnd.Close()
		writeEnd.Close()
	})

	want := openFDCount(t)
	header := controlHeader(REQ_SET_OWNER, 1, 0)
	n, oobn, err := peer.WriteMsgUnix(header, syscall.UnixRights(int(readEnd.Fd())), nil)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(header) || oobn == 0 {
		t.Fatalf("WriteMsgUnix = (%d, %d), want (%d, >0)", n, oobn, len(header))
	}

	if err := server.oneRequest(); err == nil {
		t.Fatal("SET_OWNER with an unexpected fd was accepted")
	}
	if got := openFDCount(t); got != want {
		t.Fatalf("received fd leaked: open fd count = %d, want %d", got, want)
	}
}

func TestOneRequestClosesExcessHeaderFDs(t *testing.T) {
	server, peer := newSecurityServer(t)
	firstRead, firstWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	secondRead, secondWrite, err := os.Pipe()
	if err != nil {
		firstRead.Close()
		firstWrite.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		firstRead.Close()
		firstWrite.Close()
		secondRead.Close()
		secondWrite.Close()
	})

	want := openFDCount(t)
	header := controlHeader(REQ_SET_OWNER, _VERSION, 0)
	n, oobn, err := peer.WriteMsgUnix(header, syscall.UnixRights(int(firstRead.Fd()), int(secondRead.Fd())), nil)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(header) || oobn == 0 {
		t.Fatalf("WriteMsgUnix = (%d, %d), want (%d, >0)", n, oobn, len(header))
	}
	if err := server.oneRequest(); err == nil {
		t.Fatal("request carrying excess fds was accepted")
	}
	if got := openFDCount(t); got != want {
		t.Fatalf("excess received fds leaked: open fd count = %d, want %d", got, want)
	}
}

func TestOneRequestClosesPayloadFDOnDeviceError(t *testing.T) {
	server, peer := newSecurityServer(t)
	readEnd, writeEnd, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		readEnd.Close()
		writeEnd.Close()
	})

	want := openFDCount(t)
	writeAll(t, peer, controlHeader(REQ_SET_VRING_CALL, 1, 8))
	payload := make([]byte, 8)
	binary.LittleEndian.PutUint64(payload, 63) // Outside the single-queue device.
	n, oobn, err := peer.WriteMsgUnix(payload, syscall.UnixRights(int(readEnd.Fd())), nil)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(payload) || oobn == 0 {
		t.Fatalf("WriteMsgUnix = (%d, %d), want (%d, >0)", n, oobn, len(payload))
	}

	_ = server.oneRequest()
	if got := openFDCount(t); got != want {
		t.Fatalf("payload fd leaked after device error: open fd count = %d, want %d", got, want)
	}
}

func TestOneRequestRejectsUnadvertisedLogFDWithoutLeak(t *testing.T) {
	server, peer := newSecurityServer(t)
	readEnd, writeEnd, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		readEnd.Close()
		writeEnd.Close()
	})

	want := openFDCount(t)
	header := controlHeader(REQ_SET_LOG_BASE, _VERSION, uint32(unsafe.Sizeof(VhostUserLog{})))
	n, oobn, err := peer.WriteMsgUnix(header, syscall.UnixRights(int(readEnd.Fd())), nil)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(header) || oobn == 0 {
		t.Fatalf("WriteMsgUnix = (%d, %d), want (%d, >0)", n, oobn, len(header))
	}
	if err := server.oneRequest(); err == nil {
		t.Fatal("unadvertised SET_LOG_BASE was accepted")
	}
	if got := openFDCount(t); got != want {
		t.Fatalf("unadvertised log fd leaked: open fd count = %d, want %d", got, want)
	}
}

func TestProtocolFeaturesDoNotAdvertiseUnusedFDChannels(t *testing.T) {
	device := NewDeviceWithQueues(1, func(*VirtqElem) int { return 0 })
	defer device.Close()

	mask := composeMask(device.GetProtocolFeatures())
	unsupported := uint64(1<<PROTOCOL_F_BACKEND_REQ | 1<<PROTOCOL_F_BACKEND_SEND_FD | 1<<PROTOCOL_F_LOG_SHMFD)
	if mask&unsupported != 0 {
		t.Fatalf("advertised unsupported fd-channel features: mask %#x", mask&unsupported)
	}
}

func newSecurityServer(t *testing.T) (*Server, *net.UnixConn) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}

	connections := make([]*net.UnixConn, 0, 2)
	for _, fd := range fds {
		file := os.NewFile(uintptr(fd), "vhostuser-security-test")
		connection, err := net.FileConn(file)
		file.Close()
		if err != nil {
			for _, connection := range connections {
				connection.Close()
			}
			t.Fatal(err)
		}
		unixConnection, ok := connection.(*net.UnixConn)
		if !ok {
			connection.Close()
			t.Fatalf("FileConn returned %T, want *net.UnixConn", connection)
		}
		connections = append(connections, unixConnection)
	}

	device := NewDeviceWithQueues(1, func(*VirtqElem) int { return 0 })
	server := NewServer(connections[0], device)
	t.Cleanup(func() {
		server.Close()
		connections[1].Close()
	})
	return server, connections[1]
}

func controlHeader(request, flags, size uint32) []byte {
	header := make([]byte, hdrSize)
	binary.LittleEndian.PutUint32(header[0:4], request)
	binary.LittleEndian.PutUint32(header[4:8], flags)
	binary.LittleEndian.PutUint32(header[8:12], size)
	return header
}

func writeAll(t *testing.T, connection *net.UnixConn, data []byte) {
	t.Helper()
	for len(data) > 0 {
		n, err := connection.Write(data)
		if err != nil {
			t.Fatal(err)
		}
		data = data[n:]
	}
}

func openFDCount(t *testing.T) int {
	t.Helper()
	directory, err := os.Open("/dev/fd")
	if err != nil {
		t.Fatal(err)
	}
	names, err := directory.Readdirnames(-1)
	directory.Close()
	if err != nil {
		t.Fatal(err)
	}
	return len(names)
}
