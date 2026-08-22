// Package mcpworker owns the untrusted _mcp-worker runtime and the bounded
// stream/capability protocol it shares with the trusted supervisor half.
package mcpworker

import (
	"encoding/hex"

	"github.com/ejpir/gantry/internal/sandbox/mcpgw"
	"github.com/ejpir/gantry/internal/workerconf"
)

const ProtocolVersion = 1

const (
	OpShutdown   = "mcp.shutdown"
	OpCredential = "mcp.credential"
	OpAudit      = "mcp.audit"
)

// Config is immutable worker bootstrap state. It contains origins and policy,
// but never credential values, secret source definitions, refresh tokens,
// guest argv, host paths, or sandbox identifiers.
type Config struct {
	Version     int            `json:"version"`
	Confinement string         `json:"confinement"`
	ConfRoot    string         `json:"confRoot,omitempty"`
	Servers     []ServerConfig `json:"servers"`
}

type ServerConfig struct {
	Name       string           `json:"name"`
	URL        string           `json:"url,omitempty"`
	Local      bool             `json:"local,omitempty"`
	Credential bool             `json:"credential,omitempty"`
	Tools      mcpgw.ToolPolicy `json:"tools,omitempty"`
}

type BootAck struct {
	OK          bool               `json:"ok"`
	Error       string             `json:"error,omitempty"`
	Confinement *workerconf.Report `json:"confinement,omitempty"`
}

type CredentialRequest struct {
	Server  string `json:"server"`
	Session string `json:"session"`
}

type CredentialResponse struct {
	Headers map[string]string `json:"headers,omitempty"`
	Redact  []string          `json:"redact,omitempty"`
}

type AuditRequest struct {
	Event mcpgw.Event `json:"event"`
}

// OpenRequest is the complete stream-open vocabulary. A peer cannot include a
// destination, URL, argv, credential reference, path, or sandbox ID.
type OpenRequest struct {
	Kind    string `json:"kind"`
	Server  string `json:"server,omitempty"`
	Session string `json:"session,omitempty"`
}

const (
	StreamGuest  = "guest"
	StreamRemote = "remote"
	StreamLocal  = "local"
)

// ValidSessionCapability reports whether value has the wire representation of
// a supervisor-issued MCP session capability. The supervisor additionally
// checks every capability against its live-session registry.
func ValidSessionCapability(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 16
}
