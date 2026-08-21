// Package mcpproto holds the wire constants for the per-sandbox MCP
// gateway channel (docs/mcp-gateway.md): the guest connects to vsock
// VsockPort, the VMM bridges the connection to <sandboxDir>/SockName where
// the daemon's gateway accepts it. Kept dependency-free so the guest
// helper can import it without growing the binary (same rule as
// credproto).
package mcpproto

const (
	// VsockPort is the guest-visible vsock port of the MCP gateway;
	// SockName is the daemon-side unix socket the VMM bridges to.
	VsockPort = 1029
	SockName  = "1029.sock"

	// MaxFrameBytes bounds one newline-delimited JSON-RPC frame in both
	// directions (guest↔gateway and gateway↔upstream). MCP tool results
	// can be large; 1 MiB matches the order of magnitude used by the
	// reference implementation for its control-plane responses.
	MaxFrameBytes = 1 << 20

	// ProtocolVersion is the MCP revision the gateway speaks and pins
	// upstreams to ("MCP-Protocol-Version" header on HTTP upstreams).
	ProtocolVersion = "2025-06-18"
)
