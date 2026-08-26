//go:build !windows

package sandbox

import (
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/ejpir/gantry/internal/sandbox/localsec"
)

const sshSocketName = "ssh.sock"

func sshEndpoint(name, dir string) string {
	return filepath.Join(dir, sshSocketName)
}

func listenSSH(name, dir string) (net.Listener, string, error) {
	path := sshEndpoint(name, dir)
	_ = os.Remove(path)
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, path, err
	}
	if err := localsec.SecureEndpoint(path); err != nil {
		_ = listener.Close()
		_ = os.Remove(path)
		return nil, path, err
	}
	return listener, path, nil
}

func dialSSH(name, dir string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout("unix", sshEndpoint(name, dir), timeout)
}

func removeSSHRuntime(name, dir string) { _ = os.Remove(sshEndpoint(name, dir)) }
