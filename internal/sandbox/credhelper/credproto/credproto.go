// Package credproto defines the wire format between the guest credential
// helper (cmd/gantry-guest) and the host broker
// (internal/sandbox/credhelper): one JSON request line, one JSON response
// line, over the vsock channel the VMM bridges to <sandboxDir>/SockName.
//
// It is deliberately a leaf package — no net, no internal imports — so
// the guest binary stays small. The guest streams this binary into the VM
// on every boot of a sandbox with bound secrets; pulling the broker's
// server machinery (net, controlproto) in would multiply the payload for
// no benefit.
package credproto

import "time"

const (
	// VsockPort is the guest-visible vsock port of the broker; SockName is
	// the host-side unix socket (inside the sandbox directory) the VMM
	// dials for guest connections to that port.
	VsockPort = 1027
	SockName  = "1027.sock"

	// MaxRequestBytes bounds one request line; MaxResponseBytes bounds one
	// response (a credential value plus envelope).
	MaxRequestBytes  = 4 << 10
	MaxResponseBytes = 64 << 10

	// ConnTimeout bounds a whole request/response exchange.
	ConnTimeout = 5 * time.Second

	// Username is the git-credential username emitted with a token. The
	// value is conventional for GitHub (x-access-token); for other forges
	// any non-empty username authenticates the same way.
	Username = "x-access-token"
)

// Request is one guest query: the host a credential is wanted for, and
// optionally the repo path git supplied (carried for audit only).
type Request struct {
	Host string `json:"host"`
	Path string `json:"path,omitempty"`
}

// Response is the broker's answer. An empty object means "no credential":
// git then falls through to any other configured helpers.
type Response struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}
