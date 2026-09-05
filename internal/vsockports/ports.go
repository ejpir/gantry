// Package vsockports defines the host services a guest may reach over vsock.
// Keeping this an explicit capability list prevents a guest-controlled port
// number from becoming an arbitrary Unix-socket pathname.
package vsockports

import (
	"fmt"
	"path/filepath"
)

const (
	RPCPort        uint32 = 1025
	CredentialPort uint32 = 1027
	MCPPort        uint32 = 1029
)

// HostSocketName returns the supervisor-owned socket for a guest-dialable
// service. Host-to-guest listener ports (such as 1026) are intentionally not
// part of this list.
func HostSocketName(port uint32) (string, bool) {
	switch port {
	case RPCPort:
		return "1025.sock", true
	case CredentialPort:
		return "1027.sock", true
	case MCPPort:
		return "1029.sock", true
	default:
		return "", false
	}
}

// HostSocketPath resolves a registered service. On Unix it also verifies that
// the final path is a socket, not a symlink. Callers must keep dir outside
// guest write authority; lstat alone is not a TOCTOU-safe sandbox.
func HostSocketPath(dir string, port uint32) (string, error) {
	name, ok := HostSocketName(port)
	if !ok {
		return "", fmt.Errorf("host port %d is not registered", port)
	}
	path := filepath.Join(dir, name)
	if err := validateHostSocket(path, port); err != nil {
		return "", err
	}
	return path, nil
}
