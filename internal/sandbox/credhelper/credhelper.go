// Package credhelper implements the host side of the credential broker: a
// bounded JSON protocol served on a per-sandbox unix socket that the VMM's
// vsock device reaches when a guest process connects to the broker port
// (guest connect to vsock port Port → VMM dials <sandboxDir>/SockName).
// The guest helper (gantry-guest credhelper, wired as git's
// credential.helper) asks for the credential bound to a host; the broker
// answers only when the request passes three gates, in order:
//
//  1. binding  — a secret must be bound to that host (-secret NAME@host);
//  2. egress   — the sandbox's network policy must allow the host, so a
//     brokered token can never outrun the firewall;
//  3. presence — the value must currently be held (a revoked secret
//     answers empty).
//
// Every decision is audit-logged with names and hosts only — never values.
// The protocol is answer-only: there is no verb by which a guest can add,
// swap, or re-point a credential. Use does not imply rebind.
package credhelper

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/ejpir/gantry/internal/sandbox/controlproto"
	"github.com/ejpir/gantry/internal/sandbox/credhelper/credproto"
	"github.com/ejpir/gantry/internal/secret"
)

// Wire format: aliased from credproto so the guest binary (cmd/gantry-guest)
// can share the protocol without importing this server's net machinery.
const (
	VsockPort        = credproto.VsockPort
	SockName         = credproto.SockName
	MaxRequestBytes  = credproto.MaxRequestBytes
	MaxResponseBytes = credproto.MaxResponseBytes
	ConnTimeout      = credproto.ConnTimeout
	Username         = credproto.Username
)

type (
	Request  = credproto.Request
	Response = credproto.Response
)

const (
	// maxConcurrent bounds in-flight exchanges; further connections are
	// closed unanswered (git retries credential lookups sparingly).
	maxConcurrent = 8
)

// Resolution is the binding/presence outcome for a requested host.
type Resolution int

const (
	// NoBinding: no secret is bound to the requested host.
	NoBinding Resolution = iota
	// NoValue: a binding exists but the value is gone (revoked, or its
	// source stopped resolving).
	NoValue
	// SourceError: a binding exists but the daemon-side source failed to
	// resolve at request time (file deleted, exec source error). The
	// broker fails closed: nothing is served, the failure is audited.
	SourceError
	// OK: a bound credential with a live value exists.
	OK
)

// Resolver atomically maps a requested host to a bound credential. The
// sandbox broker supplies it; it must snapshot under its own lock so the
// binding and the value can never race each other.
type Resolver func(host string) (name string, value secret.Value, res Resolution)

// HostMatches reports whether a binding pattern covers a request host:
// exact match, or "*.suffix" covering subdomains and the bare suffix — the
// same semantics as the egress allowlist.
func HostMatches(pattern, host string) bool {
	pattern = strings.ToLower(strings.TrimSuffix(pattern, "."))
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if suffix, ok := strings.CutPrefix(pattern, "*."); ok {
		return host == suffix || strings.HasSuffix(host, "."+suffix)
	}
	return pattern == host
}

// NewResolver builds a Resolver over a snapshot of the secret set: values
// keyed by clean secret name, bindings mapping name → host pattern.
func NewResolver(values map[string]secret.Value, bindings map[string]string) Resolver {
	// Deterministic precedence when several bindings cover one host: sort
	// names once at snapshot time.
	names := make([]string, 0, len(bindings))
	for name := range bindings {
		names = append(names, name)
	}
	for i := 1; i < len(names); i++ { // insertion sort; binding sets are tiny
		for j := i; j > 0 && names[j] < names[j-1]; j-- {
			names[j], names[j-1] = names[j-1], names[j]
		}
	}
	return func(host string) (string, secret.Value, Resolution) {
		for _, name := range names {
			if !HostMatches(bindings[name], host) {
				continue
			}
			v, ok := values[name]
			if !ok {
				return name, "", NoValue
			}
			return name, v, OK
		}
		return "", "", NoBinding
	}
}

// Broker serves the credential protocol on one listener.
type Broker struct {
	resolve Resolver
	allowed func(host string) bool // egress gate; nil means unrestricted
	logf    func(format string, a ...any)
	// oauth routes oauth.* ops to the daemon's custody manager; nil when
	// custody mode is off (ops then answer with an error, never hang).
	oauth func(Request) Response

	slots chan struct{}
}

// New wires a Broker. logf may be nil (decisions are discarded), but should
// not be: the audit trail is the point.
func New(resolve Resolver, allowed func(host string) bool, logf func(string, ...any)) *Broker {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Broker{resolve: resolve, allowed: allowed, logf: logf, slots: make(chan struct{}, maxConcurrent)}
}

// Serve accepts connections until the listener fails (sandbox teardown
// closes it). Per-connection errors are logged and swallowed.
func (b *Broker) Serve(ln net.Listener) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		select {
		case b.slots <- struct{}{}:
			go func() {
				defer func() { <-b.slots }()
				b.exchange(c)
			}()
		default:
			b.logf("credhelper: connection dropped (concurrency limit)")
			_ = c.Close()
		}
	}
}

// SetOAuthHandler routes oauth.* protocol ops (custody login) to the
// daemon's custody manager.
func (b *Broker) SetOAuthHandler(h func(Request) Response) { b.oauth = h }

// Decide evaluates the gates for one request and returns the response. It
// is the whole policy of the broker, separated from I/O for tests.
func (b *Broker) Decide(req Request) Response {
	if req.Op != "" {
		if b.oauth == nil {
			return Response{Error: "oauth custody is not enabled for this sandbox (start with -oauth-custody)"}
		}
		return b.oauth(req)
	}
	host := strings.ToLower(strings.TrimSpace(req.Host))
	if err := secret.ValidateBinding(host); err != nil {
		b.logf("credhelper: rejected malformed host %q", req.Host)
		return Response{}
	}
	name, value, res := b.resolve(host)
	switch res {
	case NoBinding:
		b.logf("credhelper: withheld credential for %s (no authorizing binding)", host)
		return Response{}
	case NoValue:
		b.logf("credhelper: withheld %s for %s (no value held)", name, host)
		return Response{}
	case SourceError:
		b.logf("credhelper: withheld %s for %s (source resolution failed)", name, host)
		return Response{}
	}
	if b.allowed != nil && !b.allowed(host) {
		b.logf("credhelper: denied %s for %s (egress policy)", name, host)
		return Response{}
	}
	b.logf("credhelper: delivered %s for %s", name, host)
	return Response{Username: Username, Password: value.Raw()}
}

// exchange runs one request/response on a connection and closes it.
func (b *Broker) exchange(c net.Conn) {
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(ConnTimeout))
	line, err := controlproto.ReadBoundedLine(bufio.NewReader(c), MaxRequestBytes)
	if err != nil {
		if !errors.Is(err, net.ErrClosed) {
			b.logf("credhelper: read request: %v", err)
		}
		return
	}
	var req Request
	if err := json.Unmarshal(line, &req); err != nil {
		b.logf("credhelper: malformed request: %v", err)
		return
	}
	resp := b.Decide(req)
	out, err := json.Marshal(resp)
	if err != nil || len(out)+1 > MaxResponseBytes {
		b.logf("credhelper: response for %s unencodable or oversized", req.Host)
		return
	}
	if _, err := fmt.Fprintf(c, "%s\n", out); err != nil {
		b.logf("credhelper: write response: %v", err)
	}
}
