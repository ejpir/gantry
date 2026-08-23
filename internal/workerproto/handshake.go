package workerproto

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"time"
)

// Role identifies one compile-time worker implementation. A role is protocol
// metadata, not authority: the inherited capability channels and launch nonce
// are what authorize a child process.
type Role string

const (
	// Magic identifies protocol version 1 of the control handshake.
	Magic = "GANTRY-WORKER/1"
	// RoleVMM owns the hypervisor and guest-facing device frontends.
	RoleVMM Role = "vmm"
	// RoleNet owns the netstack, policy, telemetry, and port listeners.
	RoleNet Role = "net"
	// RoleMCP parses guest and upstream MCP traffic while host authority stays
	// behind supervisor-owned capability brokers.
	RoleMCP Role = "mcp"
	// RoleWHPX is the narrow Windows hypervisor broker. It owns the opaque
	// partition object but no guest disks, shares, network, or console handles.
	RoleWHPX Role = "whpx"

	nonceLen         = 32
	handshakeTimeout = 15 * time.Second
)

// Valid reports whether the role names a compiled worker implementation.
func (r Role) Valid() bool {
	switch r {
	case RoleVMM, RoleNet, RoleMCP, RoleWHPX:
		return true
	default:
		return false
	}
}

// Handshake is the first and only supervisor-to-worker control message that
// is not a Request. Config is already parsed and normalized by the supervisor.
type Handshake struct {
	Magic  string          `json:"magic"`
	Role   Role            `json:"role"`
	Nonce  string          `json:"nonce"`
	Config json.RawMessage `json:"config"`
}

// NewNonce generates a fresh raw launch nonce.
func NewNonce() ([]byte, error) {
	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("workerproto: generate nonce: %w", err)
	}
	return nonce, nil
}

// WriteNonce sends the raw launch nonce as the first bytes on a data channel.
func WriteNonce(w io.Writer, nonce []byte) error {
	if len(nonce) != nonceLen {
		return fmt.Errorf("workerproto: nonce length %d", len(nonce))
	}
	if err := writeOnce(w, nonce); err != nil {
		return fmt.Errorf("workerproto: write nonce: %w", err)
	}
	return nil
}

// ReadNonce validates the data-channel nonce against the control handshake.
func ReadNonce(r io.Reader, want []byte) error {
	if len(want) != nonceLen {
		return fmt.Errorf("workerproto: expected nonce length %d", len(want))
	}
	var got [nonceLen]byte
	if _, err := io.ReadFull(r, got[:]); err != nil {
		return fmt.Errorf("workerproto: read nonce: %w", err)
	}
	if !bytes.Equal(got[:], want) {
		return fmt.Errorf("workerproto: data-channel nonce mismatch (cross-wired launch?)")
	}
	return nil
}

// ServeHandshake reads and validates the worker side of a handshake. The
// bootstrap deadline is cleared before returning.
func ServeHandshake(conn net.Conn, wantRole Role, config any) ([]byte, error) {
	if !wantRole.Valid() {
		return nil, fmt.Errorf("workerproto: invalid expected role %q", wantRole)
	}
	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))
	defer func() { _ = conn.SetDeadline(time.Time{}) }()

	var handshake Handshake
	if err := ReadMessage(conn, &handshake); err != nil {
		return nil, err
	}
	if handshake.Magic != Magic {
		return nil, fmt.Errorf("workerproto: bad magic %q", handshake.Magic)
	}
	if handshake.Role != wantRole {
		return nil, fmt.Errorf("workerproto: bad role %q (want %q)", handshake.Role, wantRole)
	}
	nonce, err := hex.DecodeString(handshake.Nonce)
	if err != nil || len(nonce) != nonceLen {
		return nil, fmt.Errorf("workerproto: malformed nonce")
	}
	if config == nil {
		return nonce, nil
	}
	if len(handshake.Config) == 0 {
		return nil, fmt.Errorf("workerproto: missing bootstrap config")
	}
	if err := json.Unmarshal(handshake.Config, config); err != nil {
		return nil, fmt.Errorf("workerproto: bootstrap config: %w", err)
	}
	return nonce, nil
}

// SendHandshake writes the supervisor side of ServeHandshake. The caller
// separately sends the same nonce on each correlated data channel.
func SendHandshake(conn net.Conn, role Role, nonce []byte, config any) error {
	if !role.Valid() {
		return fmt.Errorf("workerproto: invalid role %q", role)
	}
	if len(nonce) != nonceLen {
		return fmt.Errorf("workerproto: nonce length %d", len(nonce))
	}
	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))
	defer func() { _ = conn.SetDeadline(time.Time{}) }()

	raw, err := json.Marshal(config)
	if err != nil {
		return err
	}
	return WriteMessage(conn, Handshake{
		Magic:  Magic,
		Role:   role,
		Nonce:  hex.EncodeToString(nonce),
		Config: raw,
	})
}
