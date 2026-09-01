//go:build windows

package sandbox

import (
	"net"
	"strings"
	"testing"
	"time"
)

func TestSSHEndpointIsScopedToCanonicalSandboxDirectory(t *testing.T) {
	name := "transport-test"
	dir := t.TempDir()
	endpoint, err := sshEndpoint(name, dir)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(endpoint, `\\.\pipe\gantry-transport-test-`) || !strings.HasSuffix(endpoint, `-ssh`) {
		t.Fatalf("pipe path = %q", endpoint)
	}
	for _, equivalent := range []string{dir + `\.`, strings.ToUpper(dir)} {
		got, err := sshEndpoint(name, equivalent)
		if err != nil {
			t.Fatal(err)
		}
		if got != endpoint {
			t.Fatalf("equivalent directory %q produced %q, want %q", equivalent, got, endpoint)
		}
	}
	other, err := sshEndpoint(name, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if other == endpoint {
		t.Fatalf("different Gantry roots share SSH endpoint %q", endpoint)
	}
}

func TestSSHNamedPipeTransport(t *testing.T) {
	name := "transport-test"
	dir := t.TempDir()
	listener, path, err := listenSSH(name, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	wantPath, err := sshEndpoint(name, dir)
	if err != nil {
		t.Fatal(err)
	}
	if path != wantPath {
		t.Fatalf("pipe path = %q, want %q", path, wantPath)
	}
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, _ := listener.Accept()
		accepted <- conn
	}()
	client, err := dialSSH(name, dir, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	server := <-accepted
	if server == nil {
		t.Fatal("named pipe accept failed")
	}
	_ = server.Close()
}
