//go:build windows

package sandbox

import (
	"net"
	"testing"
	"time"
)

func TestSSHNamedPipeTransport(t *testing.T) {
	name := "transport-test"
	listener, path, err := listenSSH(name, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	if path != `\\.\pipe\gantry-transport-test-ssh` {
		t.Fatalf("pipe path = %q", path)
	}
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, _ := listener.Accept()
		accepted <- conn
	}()
	client, err := dialSSH(name, "", time.Second)
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
