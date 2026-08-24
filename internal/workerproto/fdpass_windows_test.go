package workerproto

import (
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWindowsSocketTransferWaitsForReconstruction(t *testing.T) {
	sender, receiver := net.Pipe()
	bound := ForProcess(sender, uint32(os.Getpid()))
	mux := NewFDMux(receiver)
	defer func() { _ = mux.Close() }()

	for iteration := 0; iteration < 20; iteration++ {
		listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		source, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
		if err != nil {
			_ = listener.Close()
			t.Fatal(err)
		}
		peer, err := listener.AcceptTCP()
		_ = listener.Close()
		if err != nil {
			_ = source.Close()
			t.Fatal(err)
		}
		file, err := source.File()
		if err != nil {
			_ = source.Close()
			_ = peer.Close()
			t.Fatal(err)
		}
		var token [FDTokenLen]byte
		if _, err := rand.Read(token[:]); err != nil {
			t.Fatal(err)
		}
		wait, err := mux.Expect(token)
		if err != nil {
			t.Fatal(err)
		}
		sent := make(chan error, 1)
		go func() { sent <- SendFD(bound, token, file) }()
		receivedFile, err := wait.Wait(5 * time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if err := <-sent; err != nil {
			t.Fatal(err)
		}
		// Closing every source-side duplicate after SendFD returns is the race
		// this acknowledgement prevents: the reconstructed socket must survive.
		_ = file.Close()
		_ = source.Close()
		received, err := net.FileConn(receivedFile)
		_ = receivedFile.Close()
		if err != nil {
			_ = peer.Close()
			t.Fatal(err)
		}
		payload := []byte("socket-transfer")
		if _, err := peer.Write(payload); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(received, got); err != nil {
			t.Fatal(err)
		}
		_ = received.Close()
		_ = peer.Close()
		if string(got) != string(payload) {
			t.Fatalf("payload = %q, want %q", got, payload)
		}
	}
}

func TestWindowsUnixSocketTransferFailsClosed(t *testing.T) {
	path := filepath.Join(os.TempDir(), fmt.Sprintf("gantry-fdpass-%d.sock", os.Getpid()))
	_ = os.Remove(path)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = listener.Close()
		_ = os.Remove(path)
	}()
	peer, err := net.DialUnix("unix", nil, listener.Addr().(*net.UnixAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = peer.Close() }()
	source, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = source.Close() }()
	file, err := source.File()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()

	sender, receiver := net.Pipe()
	defer func() { _ = sender.Close() }()
	defer func() { _ = receiver.Close() }()
	var token [FDTokenLen]byte
	if _, err := rand.Read(token[:]); err != nil {
		t.Fatal(err)
	}
	err = SendFD(ForProcess(sender, uint32(os.Getpid())), token, file)
	if err == nil {
		t.Fatal("AF_UNIX transfer succeeded; expected supervisor-relay requirement")
	}
	if !strings.Contains(err.Error(), "AF_UNIX sockets require a supervisor-owned relay") {
		t.Fatalf("AF_UNIX transfer error = %v", err)
	}
}

func TestWindowsConcurrentSocketTransfersAreSerialized(t *testing.T) {
	sender, receiver := net.Pipe()
	bound := ForProcess(sender, uint32(os.Getpid()))
	mux := NewFDMux(receiver)
	defer func() { _ = mux.Close() }()

	type transfer struct {
		source *net.TCPConn
		peer   *net.TCPConn
		file   *os.File
		wait   *FDWait
		sent   chan error
	}
	const count = 16
	transfers := make([]transfer, 0, count)
	for range count {
		listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		source, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
		if err != nil {
			t.Fatal(err)
		}
		peer, err := listener.AcceptTCP()
		_ = listener.Close()
		if err != nil {
			t.Fatal(err)
		}
		file, err := source.File()
		if err != nil {
			t.Fatal(err)
		}
		var token [FDTokenLen]byte
		if _, err := rand.Read(token[:]); err != nil {
			t.Fatal(err)
		}
		wait, err := mux.Expect(token)
		if err != nil {
			t.Fatal(err)
		}
		sent := make(chan error, 1)
		transfers = append(transfers, transfer{source: source, peer: peer, file: file, wait: wait, sent: sent})
		go func() { sent <- SendFD(bound, token, file) }()
	}

	for index, transfer := range transfers {
		receivedFile, err := transfer.wait.Wait(5 * time.Second)
		if err != nil {
			t.Fatalf("transfer %d receive: %v", index, err)
		}
		if err := <-transfer.sent; err != nil {
			t.Fatalf("transfer %d send: %v", index, err)
		}
		_ = transfer.file.Close()
		_ = transfer.source.Close()
		received, err := net.FileConn(receivedFile)
		_ = receivedFile.Close()
		if err != nil {
			t.Fatalf("transfer %d import: %v", index, err)
		}
		payload := []byte(fmt.Sprintf("socket-transfer-%d", index))
		if _, err := transfer.peer.Write(payload); err != nil {
			t.Fatalf("transfer %d write: %v", index, err)
		}
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(received, got); err != nil {
			t.Fatalf("transfer %d read: %v", index, err)
		}
		_ = received.Close()
		_ = transfer.peer.Close()
		if string(got) != string(payload) {
			t.Fatalf("transfer %d payload = %q, want %q", index, got, payload)
		}
	}
}
