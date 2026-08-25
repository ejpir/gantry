//go:build !windows

package sandbox

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSSHListenerIsPrivateLocalSocket(t *testing.T) {
	dir := t.TempDir()
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
