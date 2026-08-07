//go:build unix

package sandbox

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

// The broker's only ctl.sock access control beyond the 0700 directory is
// the kernel-verified peer UID: a same-account connection must be accepted
// (a false negative here would break every CLI op), and the UID the kernel
// reports must be the real one — not anything the client sends.
func TestPeerSameUser(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "ctl.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	server := <-accepted
	defer server.Close()

	uid, err := peerUID(server)
	if err != nil {
		t.Fatal("peerUID:", err)
	}
	if int(uid) != os.Geteuid() {
		t.Fatalf("kernel reports peer UID %d, our euid is %d", uid, os.Geteuid())
	}
	if !peerSameUser(server) {
		t.Fatal("same-account connection must pass the broker gate")
	}
}
