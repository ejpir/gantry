// Package controlproto is the wire contract for a sandbox's ctl.sock: the
// request and response frames, the session sub-protocol, and the bounded
// framing both ends must agree on.
//
// The daemon's broker serves it; `gantry share/port/net-policy`, the exec
// client and the dashboard call it. Keeping the types here is what stops the
// two sides from drifting.
package controlproto

import (
	"github.com/ejpir/gantry/internal/packetcapture"
	"github.com/ejpir/gantry/internal/sandbox/control"
	"github.com/ejpir/gantry/internal/secret"
	"github.com/ejpir/gantry/internal/shares"
)

type Request struct {
	Op        string                 `json:"op"` // "session" | "sessionctl" | "kill" | "share.*" | "port.*" | "resources.set"
	ID        string                 `json:"id"`
	V         int                    `json:"v,omitempty"` // sessionctl: SessionProtocolVersion
	Args      []string               `json:"args,omitempty"`
	Cwd       string                 `json:"cwd,omitempty"`
	Cols      uint32                 `json:"cols,omitempty"`
	Rows      uint32                 `json:"rows,omitempty"`
	Terminal  bool                   `json:"terminal,omitempty"`
	Quiet     bool                   `json:"quiet,omitempty"`
	Share     *ShareRequest          `json:"share,omitempty"`
	Port      *PortRequest           `json:"port,omitempty"`
	Resources *ResourceRequest       `json:"resources,omitempty"`
	NetPolicy *NetworkPolicyRequest  `json:"net_policy,omitempty"`
	Secret    *SecretRequest         `json:"secret,omitempty"`
	Capture   *packetcapture.Request `json:"capture,omitempty"`
}

type ResourceRequest struct {
	MemMB            uint   `json:"mem_mb"`
	VCPUs            int    `json:"vcpus"`
	ProcessIsolation string `json:"process_isolation,omitempty"`
}

type ResourceResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

type SecretRequest struct {
	Name  string       `json:"name"`
	Value secret.Value `json:"value,omitempty"`
}

type SecretResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// AuditResponse answers audit.tail: the broker's bounded in-memory trail
// of security-relevant events (credential deliveries/withholds, secret
// source errors, custody events). Oldest first; at most 256 entries.
type AuditResponse struct {
	Lines []string `json:"lines,omitempty"`
	Error string   `json:"error,omitempty"`
}

type ShareRequest struct {
	Spec       string `json:"spec,omitempty"`
	Tag        string `json:"tag,omitempty"`
	Persistent bool   `json:"persistent"`
	Replace    bool   `json:"replace,omitempty"`
	Force      bool   `json:"force,omitempty"`
}

type ShareResponse struct {
	OK         bool           `json:"ok"`
	Error      string         `json:"error,omitempty"`
	Generation uint64         `json:"generation,omitempty"`
	Entry      *shares.Entry  `json:"entry,omitempty"`
	Shares     []shares.Entry `json:"shares,omitempty"`
}

type PortRequest struct {
	Spec       string `json:"spec"`
	Persistent bool   `json:"persistent"`
}

type PortResponse struct {
	OK    bool                `json:"ok"`
	Error string              `json:"error,omitempty"`
	Entry *control.PortEntry  `json:"entry,omitempty"`
	Ports []control.PortEntry `json:"ports,omitempty"`
}

type NetworkPolicyRequest struct {
	Path       string `json:"path,omitempty"`
	AllowLocal bool   `json:"allow_local"`
}

type NetworkPolicyResponse struct {
	OK     bool                        `json:"ok"`
	Error  string                      `json:"error,omitempty"`
	Policy *control.NetworkPolicyEntry `json:"policy,omitempty"`
}

// SessionProtocolVersion versions the session-control channel: the
// "sessionctl" request carries it and every SessionExitEvent echoes it,
// so agent integrations have a stable, checkable contract. Bump on any
// wire change.
const (
	SessionProtocolVersion  = 1
	SessionAbnormalExitCode = 255
)

// SessionExitEvent is the single message a session-control channel
// carries after the handshake: the task's exit status, delivered out of
// band (never inline in the stdio stream).
type SessionExitEvent struct {
	V     int    `json:"v"`
	Exit  int    `json:"exit"`
	Error string `json:"error,omitempty"`
}
