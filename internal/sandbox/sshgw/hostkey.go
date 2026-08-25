package sshgw

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ejpir/gantry/internal/atomicfile"
	"github.com/ejpir/gantry/internal/gutil"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// EnsureHostKey loads the install-wide SSH host key, creating an Ed25519 key
// atomically on first use. An existing malformed key is never replaced: doing
// so silently would defeat the KnownHostsCommand pin.
func EnsureHostKey(path string) (ssh.Signer, error) {
	if path == "" {
		return nil, errors.New("SSH host key path is empty")
	}
	if err := secureSSHStateDir(filepath.Dir(path)); err != nil {
		return nil, fmt.Errorf("secure SSH state directory: %w", err)
	}
	lock, err := gutil.LockFile(path + ".lock")
	if err != nil {
		return nil, fmt.Errorf("lock SSH host key %s: %w", path, err)
	}
	defer func() { _ = lock.Close() }()

	data, err := os.ReadFile(path)
	if err == nil {
		if err := secureSSHPrivateFile(path); err != nil {
			return nil, fmt.Errorf("secure SSH host key %s: %w", path, err)
		}
		return parseHostKey(path, data)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read SSH host key %s: %w", path, err)
	}

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate SSH host key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("encode SSH host key: %w", err)
	}
	data = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := atomicfile.WriteFileDurable(path, data, 0o600); err != nil {
		return nil, fmt.Errorf("write SSH host key %s: %w", path, err)
	}
	if err := secureSSHPrivateFile(path); err != nil {
		return nil, fmt.Errorf("secure SSH host key %s: %w", path, err)
	}
	return parseHostKey(path, data)
}

func parseHostKey(path string, data []byte) (ssh.Signer, error) {
	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("SSH host key %s is corrupt: %w; delete it to regenerate the install key", path, err)
	}
	if signer.PublicKey().Type() != ssh.KeyAlgoED25519 {
		return nil, fmt.Errorf("SSH host key %s is not Ed25519; delete it to regenerate the install key", path)
	}
	return signer, nil
}

// KnownHostsLine returns one OpenSSH known_hosts entry for the install key.
func KnownHostsLine(path, host string) (string, error) {
	signer, err := EnsureHostKey(path)
	if err != nil {
		return "", err
	}
	if host == "" {
		host = "*.gantry"
	}
	return knownhosts.Line([]string{host}, signer.PublicKey()), nil
}
