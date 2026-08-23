package vmmworker

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ejpir/gantry/internal/sandbox/worker"
)

func TestWindowsSplitVMMDoesNotRequireNetworkOrShareAttachment(t *testing.T) {
	if !vmmSplitPossible("required", nil, nil) {
		t.Fatal("required split VMM rejected an offline, shareless topology")
	}
	if vmmSplitPossible("off", nil, nil) {
		t.Fatal("off mode enabled the split VMM")
	}
}

func TestWindowsVsockRelayCarriesUnixSocketTraffic(t *testing.T) {
	path := filepath.Join(os.TempDir(), fmt.Sprintf("gantry-vsock-relay-%d.sock", os.Getpid()))
	_ = os.Remove(path)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = listener.Close()
		_ = os.Remove(path)
	}()
	host, err := net.DialUnix("unix", nil, listener.Addr().(*net.UnixAddr))
	if err != nil {
		t.Fatal(err)
	}
	peer, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = peer.Close() }()
	supervisor, target, err := worker.SocketpairConns()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = target.Close() }()
	go relayWindowsVsock(supervisor, host)

	request := []byte("guest-to-host")
	if _, err := target.Write(request); err != nil {
		t.Fatal(err)
	}
	if err := peer.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(request))
	if _, err := io.ReadFull(peer, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(request) {
		t.Fatalf("host read %q, want %q", got, request)
	}

	response := []byte("host-to-guest")
	if _, err := peer.Write(response); err != nil {
		t.Fatal(err)
	}
	if err := target.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	got = make([]byte, len(response))
	if _, err := io.ReadFull(target, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(response) {
		t.Fatalf("guest read %q, want %q", got, response)
	}
}
