//go:build linux || darwin

package virtio

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestVsockHostDialRejectsSymlinkEndpoint(t *testing.T) {
	root, err := os.MkdirTemp("/tmp", "gantry-vsock-security-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	outsidePath := filepath.Join(root, "outside.sock")
	listener, err := net.Listen("unix", outsidePath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()

	forwardDir := filepath.Join(root, "forward")
	if err := os.Mkdir(forwardDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsidePath, filepath.Join(forwardDir, "1025.sock")); err != nil {
		t.Fatal(err)
	}
	vsock := NewVsock(3, forwardDir)
	connection, err := vsock.dial(1025)
	if err == nil {
		_ = connection.Close()
		t.Fatal("registered guest port reached an external unix socket through a symlink")
	}

	if unixListener, ok := listener.(*net.UnixListener); ok {
		_ = unixListener.SetDeadline(time.Now().Add(50 * time.Millisecond))
	}
	accepted, acceptErr := listener.Accept()
	if acceptErr == nil {
		_ = accepted.Close()
		t.Fatal("external unix socket accepted a symlinked guest connection")
	}
}
