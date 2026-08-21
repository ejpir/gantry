package sandbox

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ejpir/gantry/internal/atomicfile"
	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/control"
	"github.com/ejpir/gantry/internal/sandbox/controlproto"
	"github.com/ejpir/gantry/internal/sandbox/credhelper"
	"github.com/ejpir/gantry/internal/sandbox/localsec"
	"github.com/ejpir/gantry/internal/sandbox/oauthbridge"
	"github.com/ejpir/gantry/internal/secret"
	"github.com/ejpir/gantry/internal/shares"

	"github.com/containerd/ttrpc"
)

// broker accepts ctl connections. Protocol: one JSON request line, then
// one JSON response line. For "session" the socket then turns into a raw
// bidirectional stdio pipe until the task exits — a PURE pipe: the exit
// status travels out of band on the session-control channel (op
// "sessionctl", parked by the client before the session starts) as a
// versioned JSON event, so guest output can contain any byte sequence
// without colliding with the protocol, and a missing event unambiguously
// means the broker died (never exit 0).
type broker struct {
	cfg        config.RunConfig
	dir        string
	rpc        *ttrpc.Client
	streamSock string
	// streamDial replaces the streamSock unix dial in the split-VMM
	// topology (streams cross the worker bridge).
	streamDial func() (net.Conn, error)
	store      *config.ConfigStore
	shares     *control.ShareManager
	ports      *control.PortManager
	netPolicy  *control.NetworkPolicyManager
	capture    packetCaptureBackend
	secrets    map[string]secret.Value // memory only, VM lifetime — never serialized
	secretMu   sync.RWMutex
	// domainAllowed is the egress gate for the credential broker (nil when
	// the sandbox has no network policy object).
	domainAllowed func(string) bool
	// cred serves the guest credential broker on <dir>/1027.sock (nil until
	// the listener is up).
	cred *credhelper.Broker
	// guestToolsReady records that gantry-guest was staged into the guest
	// this boot; secretEnv wires git's credential.helper only when set.
	guestToolsReady atomic.Bool

	mu         sync.Mutex
	sessions   map[string]chan struct{}
	sessionCtl map[string]net.Conn // parked control channels, session id -> conn
	oauth      *oauthbridge.Bridge // OAuth loopback callback bridge (nil when disabled)
	limits     brokerLimits
	shutdown   chan<- struct{} // authenticated daemon shutdown request
}

func (br *broker) serve(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		// ctl.sock has no request authentication: the 0700 sandbox dir
		// plus this kernel-verified peer-UID check are the access
		// control, and the trust domain is the user account (a same-UID
		// process could present any credential we could issue — token or
		// TLS would be ceremony, not security). If this socket is EVER
		// relayed over TCP, real authentication (mTLS) is mandatory.
		if !localsec.PeerSameUser(c) {
			fmt.Fprintln(os.Stderr, "daemon: rejected ctl.sock connection from a foreign UID")
			_ = c.Close()
			continue
		}
		if !br.limits.acquireConnection() {
			_ = c.SetWriteDeadline(time.Now().Add(controlproto.OverloadTimeout))
			_, _ = fmt.Fprintln(c, `{"error":"too many control connections"}`)
			_ = c.Close()
			continue
		}
		go func(c net.Conn) {
			defer br.limits.releaseConnection()
			br.handle(c)
		}(c)
	}
}

func (br *broker) handle(c net.Conn) {
	defer func() { _ = c.Close() }()
	_ = c.SetReadDeadline(time.Now().Add(controlproto.HandshakeTimeout))
	r := bufio.NewReader(c)
	line, err := controlproto.ReadBoundedLine(r, controlproto.MaxRequestBytes)
	_ = c.SetReadDeadline(time.Time{})
	if err != nil {
		if errors.Is(err, controlproto.ErrFrameTooLarge) {
			_ = c.SetWriteDeadline(time.Now().Add(controlproto.OverloadTimeout))
			_, _ = fmt.Fprintln(c, `{"error":"control request too large"}`)
		}
		return
	}
	_ = c.SetWriteDeadline(time.Now().Add(controlproto.CallTimeout))
	var req controlproto.Request
	if json.Unmarshal(line, &req) != nil || req.ID == "" {
		_, _ = fmt.Fprintln(c, `{"error":"bad request"}`)
		return
	}
	switch req.Op {
	case "daemon.shutdown":
		if br.shutdown == nil {
			_, _ = fmt.Fprintln(c, `{"error":"shutdown unavailable"}`)
			return
		}
		// A duplicate request is already satisfied; never block a broker
		// handler while the daemon is flushing the guest.
		select {
		case br.shutdown <- struct{}{}:
		default:
		}
		_, _ = fmt.Fprintln(c, `{"ok":true}`)
	case "kill":
		br.mu.Lock()
		killCh, ok := br.sessions[req.ID]
		if ok {
			close(killCh)
			delete(br.sessions, req.ID)
		}
		br.mu.Unlock()
		if !ok {
			_, _ = fmt.Fprintln(c, `{"error":"no such session"}`)
			return
		}
		_, _ = fmt.Fprintln(c, `{"ok":true}`)
	case "share.add", "share.remove", "share.list", "share.configure":
		br.shareControl(c, req)
	case "port.publish", "port.unpublish", "port.list":
		br.portControl(c, req)
	case "resources.set":
		br.resourceControl(c, req)
	case "netpolicy.set", "netpolicy.get":
		br.networkPolicyControl(c, req)
	case "secret.set", "secret.remove":
		br.secretControl(c, req)
	case "capture.read":
		br.captureControl(c, req)
	case "session":
		br.session(c, r, req)
	case "sessionctl":
		br.sessionctl(c, r, req)
	default:
		_, _ = fmt.Fprintln(c, `{"error":"unknown op"}`)
	}
}

func (br *broker) secretControl(c net.Conn, req controlproto.Request) {
	respond := func(resp controlproto.SecretResponse) { _ = json.NewEncoder(c).Encode(&resp) }
	if br.store == nil {
		respond(controlproto.SecretResponse{Error: "config store unavailable"})
		return
	}
	if req.Secret == nil {
		respond(controlproto.SecretResponse{Error: "secret settings are required"})
		return
	}
	if err := secret.ValidateName(req.Secret.Name); err != nil {
		respond(controlproto.SecretResponse{Error: err.Error()})
		return
	}
	br.secretMu.Lock()
	defer br.secretMu.Unlock()
	present := req.Op == "secret.set"
	next := make(map[string]secret.Value, len(br.secrets)+1)
	for name, value := range br.secrets {
		next[name] = value
	}
	if present {
		next[req.Secret.Name] = req.Secret.Value
	} else {
		delete(next, req.Secret.Name)
	}
	if _, err := secretsHandshakeJSON(next); err != nil {
		respond(controlproto.SecretResponse{Error: err.Error()})
		return
	}
	err := br.store.SetSecretName(req.Secret.Name, present)
	if err != nil && !atomicfile.Committed(err) {
		respond(controlproto.SecretResponse{Error: err.Error()})
		return
	}
	br.secrets = next
	if err != nil {
		respond(controlproto.SecretResponse{Error: "secret updated but configuration durability is uncertain: " + err.Error()})
		return
	}
	respond(controlproto.SecretResponse{OK: true})
}

func (br *broker) secretEnv() []string {
	br.secretMu.RLock()
	defer br.secretMu.RUnlock()
	copy := make(map[string]secret.Value, len(br.secrets))
	for name, value := range br.secrets {
		copy[name] = value
	}
	// Bound secrets (NAME@host) are delivered through the credential broker
	// only — injecting them into every session's environment would defeat
	// the binding.
	var bound int
	if bindings := br.secretBindings(); bindings != nil {
		for name := range copy {
			if bindings[name] != "" {
				delete(copy, name)
				bound++
			}
		}
	}
	env := secret.Env(copy)
	// With a bound secret held and the helper staged, point git at the
	// broker via ephemeral env config — no guest file is ever written.
	if bound > 0 && br.guestToolsReady.Load() {
		env = append(env,
			"GIT_CONFIG_COUNT=1",
			"GIT_CONFIG_KEY_0=credential.helper",
			"GIT_CONFIG_VALUE_0=/run/gantry/bin/credhelper",
		)
	}
	return env
}

// secretBindings maps secret name → host binding, derived from the
// persisted SecretNames (the same names gantry ls shows). Caller holds
// secretMu. Returns nil when bindings are unavailable (no store or a
// corrupt persisted entry) — callers then fail closed.
func (br *broker) secretBindings() map[string]string {
	if br.store == nil {
		return nil
	}
	bindings, err := secret.BindingsFromNames(br.store.Snapshot().SecretNames)
	if err != nil {
		fmt.Printf("daemon: persisted secret names unusable (%v); failing closed\n", err)
		return nil
	}
	return bindings
}

// resolveCredential implements credhelper.Resolver over the live secret
// set: binding and value resolve under one lock so they can never race.
func (br *broker) resolveCredential(host string) (string, secret.Value, credhelper.Resolution) {
	br.secretMu.RLock()
	defer br.secretMu.RUnlock()
	bindings := br.secretBindings()
	if bindings == nil {
		return "", "", credhelper.NoBinding
	}
	return credhelper.NewResolver(br.secrets, bindings)(host)
}

func (br *broker) resourceControl(c net.Conn, req controlproto.Request) {
	respond := func(resp controlproto.ResourceResponse) {
		_ = json.NewEncoder(c).Encode(&resp)
	}
	if br.store == nil {
		respond(controlproto.ResourceResponse{Error: "config store unavailable"})
		return
	}
	if req.Resources == nil {
		respond(controlproto.ResourceResponse{Error: "resource settings are required"})
		return
	}
	if err := br.store.SetResources(req.Resources.MemMB, req.Resources.VCPUs, req.Resources.ProcessIsolation); err != nil {
		respond(controlproto.ResourceResponse{Error: err.Error()})
		return
	}
	respond(controlproto.ResourceResponse{OK: true})
}

func (br *broker) networkPolicyControl(c net.Conn, req controlproto.Request) {
	respond := func(resp controlproto.NetworkPolicyResponse) {
		_ = json.NewEncoder(c).Encode(&resp)
	}
	if br.netPolicy == nil {
		respond(controlproto.NetworkPolicyResponse{Error: "network policy manager unavailable"})
		return
	}
	var entry control.NetworkPolicyEntry
	var err error
	if req.Op == "netpolicy.set" {
		if req.NetPolicy == nil {
			respond(controlproto.NetworkPolicyResponse{Error: "network policy settings are required"})
			return
		}
		entry, err = br.netPolicy.Set(req.NetPolicy.Path, req.NetPolicy.AllowLocal)
	} else {
		entry, err = br.netPolicy.Get()
	}
	if err != nil {
		respond(controlproto.NetworkPolicyResponse{Error: err.Error()})
		return
	}
	respond(controlproto.NetworkPolicyResponse{OK: true, Policy: &entry})
}

func (br *broker) shareControl(c net.Conn, req controlproto.Request) {
	respond := func(resp controlproto.ShareResponse) {
		_ = json.NewEncoder(c).Encode(&resp)
	}
	spec := controlproto.ShareRequest{Persistent: true}
	if req.Share != nil {
		spec = *req.Share
	}
	var entry shares.Entry
	var err error
	if req.Op == "share.configure" {
		if br.shares == nil {
			respond(controlproto.ShareResponse{Error: "share manager unavailable"})
			return
		}
		configured, configureErr := br.shares.ConfigureRestart(spec.Spec, spec.Replace)
		if configureErr != nil {
			respond(controlproto.ShareResponse{Error: configureErr.Error()})
			return
		}
		entry = shares.Entry{
			Tag: configured.Tag, Path: configured.Path, RO: configured.RO,
			UID: configured.UID, GID: configured.GID,
			VMPath:  shares.HubVMPath + "/" + configured.Tag,
			CtrPath: config.ConfiguredShareTarget(configured), State: "restart",
		}
		respond(controlproto.ShareResponse{OK: true, Entry: &entry})
		return
	}
	if br.shares == nil {
		respond(controlproto.ShareResponse{Error: "share manager unavailable"})
		return
	}
	switch req.Op {
	case "share.add":
		entry, err = br.shares.Add(spec.Spec, spec.Persistent, spec.Replace)
	case "share.remove":
		entry, err = br.shares.Remove(spec.Tag, spec.Persistent, spec.Force)
	case "share.list":
		respond(controlproto.ShareResponse{OK: true, Generation: br.shares.Generation(), Shares: br.shares.Entries()})
		return
	}
	if err != nil {
		respond(controlproto.ShareResponse{Error: err.Error(), Generation: br.shares.Generation()})
		return
	}
	respond(controlproto.ShareResponse{OK: true, Generation: br.shares.Generation(), Entry: &entry})
}

func (br *broker) portControl(c net.Conn, req controlproto.Request) {
	respond := func(resp controlproto.PortResponse) {
		_ = json.NewEncoder(c).Encode(&resp)
	}
	if br.ports == nil {
		respond(controlproto.PortResponse{Error: "port manager unavailable"})
		return
	}
	spec := controlproto.PortRequest{Persistent: true}
	if req.Port != nil {
		spec = *req.Port
	}
	var entry control.PortEntry
	var err error
	switch req.Op {
	case "port.publish":
		entry, err = br.ports.Publish(spec.Spec, spec.Persistent)
	case "port.unpublish":
		entry, err = br.ports.Unpublish(spec.Spec, spec.Persistent)
	case "port.list":
		ports, lerr := br.ports.List()
		if lerr != nil {
			respond(controlproto.PortResponse{Error: lerr.Error()})
			return
		}
		respond(controlproto.PortResponse{OK: true, Ports: ports})
		return
	}
	if err != nil {
		respond(controlproto.PortResponse{Error: err.Error()})
		return
	}
	respond(controlproto.PortResponse{OK: true, Entry: &entry})
}
