//go:build windows

package sandbox

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"time"

	"github.com/Microsoft/go-winio"
	"github.com/ejpir/gantry/internal/sandbox/localsec"
)

func sshEndpoint(name, dir string) (string, error) {
	canonicalDir, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("resolve SSH sandbox directory %q: %w", dir, err)
	}
	canonicalDir, err = filepath.EvalSymlinks(canonicalDir)
	if err != nil {
		return "", fmt.Errorf("canonicalize SSH sandbox directory %q: %w", dir, err)
	}
	// Windows paths are case-insensitive. Normalize case before hashing so a
	// client using a differently cased GANTRY_HOME still reaches the daemon.
	canonicalDir = strings.ToLower(filepath.Clean(canonicalDir))
	scope := sha256.Sum256([]byte(canonicalDir))
	return fmt.Sprintf(`\\.\pipe\gantry-%s-%x-ssh`, name, scope[:16]), nil
}

func listenSSH(name, dir string) (net.Listener, string, error) {
	path, err := sshEndpoint(name, dir)
	if err != nil {
		return nil, "", err
	}
	userSID, err := localsec.CurrentUserSID()
	if err != nil {
		return nil, path, err
	}
	// Protected DACL: administrators and SYSTEM get full access; the owning
	// user gets only the read/write rights needed to carry SSH bytes.
	sddl := fmt.Sprintf(`D:P(A;;GA;;;BA)(A;;GA;;;SY)(A;;GRGW;;;%s)`, userSID.String())
	listener, err := winio.ListenPipe(path, &winio.PipeConfig{
		SecurityDescriptor: sddl,
		InputBufferSize:    1 << 20,
		OutputBufferSize:   1 << 20,
	})
	return listener, path, err
}

func dialSSH(name, dir string, timeout time.Duration) (net.Conn, error) {
	path, err := sshEndpoint(name, dir)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return winio.DialPipeContext(ctx, path)
}

func removeSSHRuntime(string, string) {}
