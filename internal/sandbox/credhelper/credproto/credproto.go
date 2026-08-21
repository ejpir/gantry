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

	// OAuth custody ops (workstream 3): the guest helper delegates the
	// authorization-code exchange to the daemon, which holds the refresh
	// token host-side and pushes fresh access tokens into the guest auth
	// file. Op empty means the classic credential-get.
	OpOAuthBegin  = "oauth.begin"
	OpOAuthStatus = "oauth.status"
)

// Request is one guest query. For a credential get: the host a credential
// is wanted for, plus optionally the repo path git supplied (audit only).
// For oauth.begin: the PKCE material and endpoints of the flow the daemon
// should complete host-side. The verifier is PKCE proof material — it
// travels only over this trusted vsock channel, never the network.
type Request struct {
	Op   string `json:"op,omitempty"`
	Host string `json:"host"`
	Path string `json:"path,omitempty"`

	Provider     string `json:"provider,omitempty"`
	State        string `json:"state,omitempty"`
	Challenge    string `json:"challenge,omitempty"`
	Verifier     string `json:"verifier,omitempty"`
	AuthorizeURL string `json:"authorizeUrl,omitempty"`
	ClientID     string `json:"clientId,omitempty"`
	RedirectURI  string `json:"redirectUri,omitempty"`
}

// Response is the broker's answer. For a credential get an empty object
// means "no credential": git then falls through to any other configured
// helpers. For oauth.* ops OK/Error/Message carry the flow state.
type Response struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`

	OK      bool   `json:"ok,omitempty"`
	Error   string `json:"error,omitempty"`
	Message string `json:"message,omitempty"`
}
