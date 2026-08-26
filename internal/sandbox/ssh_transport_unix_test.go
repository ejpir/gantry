//go:build !windows

package sandbox

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSSHListenerIsPrivateLocalSocket(t *testing.T) {
	// macOS limits Unix-domain socket paths to 104 bytes, while t.TempDir's
	// test-derived directory name can exceed that before ssh.sock is appended.
	// Production sockets share the already-short sandbox runtime directory.
	dir, err := os.MkdirTemp("", "gantry-ssh-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	listener, path, err := listenSSH("demo", dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	if path != filepath.Join(dir, sshSocketName) {
		t.Fatalf("endpoint = %q", path)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o600 {
		t.Fatalf("SSH endpoint mode = %v, want socket 0600", info.Mode())
	}
}
