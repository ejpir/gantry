package sandbox

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ejpir/gantry/internal/atomicfile"
	"github.com/ejpir/gantry/internal/policy"
	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/control"
	"github.com/ejpir/gantry/internal/sandbox/controlproto"
	"github.com/ejpir/gantry/internal/sandbox/credhelper"
	"github.com/ejpir/gantry/internal/sandbox/guestplane"
	"github.com/ejpir/gantry/internal/sandbox/localsec"
	"github.com/ejpir/gantry/internal/sandbox/oauthbridge"
	"github.com/ejpir/gantry/internal/sandbox/oauthtokens"
	sandboxsupervisor "github.com/ejpir/gantry/internal/sandbox/supervisor"
	"github.com/ejpir/gantry/internal/secret"
	"github.com/ejpir/gantry/internal/shares"
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
	rpc        guestplane.RPC
	streamSock string
	// streamDial replaces the streamSock unix dial in the split-VMM
	// topology (streams cross the worker bridge).
	streamDial     func() (net.Conn, error)
	sessionSetupMu sync.Mutex
	store          configStoreBorrow
	shares         shareManagerBorrow
	ports          portManagerBorrow
	netPolicy      *control.NetworkPolicyManager
	capture        packetCaptureBackend
	// secretStore resolves values at use time (source TTL, fail-closed);
	// memory only, VM lifetime — never serialized.
	secretStore *secret.Store
	secretMu    sync.Mutex // orders control-socket sets against persistence
	// domainAllowed is the egress gate for the credential broker (nil when
	// the sandbox has no network policy object).
	domainAllowed func(string) bool
	// cred serves the guest credential broker on <dir>/1027.sock (nil until
	// the listener is up).
	cred *credhelper.Broker
	// Workload and IDE roots track helper verification independently. Bound
	// credentials consume the workload state; SSH waits on the root selected by
	// the active Dev Containers topology.
	guestToolsReady    atomic.Bool // workload OCI root
	guestToolsDone     chan struct{}
	guestToolsDoneOnce sync.Once
	ideToolsReady      atomic.Bool // curated IDE OCI root
	ideToolsDone       chan struct{}
	ideToolsDoneOnce   sync.Once
	// devContainers is live configuration: configure updates it without
	// restarting the VM, and newly created user sessions read it atomically.
	devContainers atomic.Bool
	configure     func(controlproto.ConfigureRequest) (bool, error)
	policyApply   func(*policy.Config) error
	// audit is the daemon-wide trail and sink writer shared with early boot
	// and policy callbacks. auditMu is only the no-ring standalone fallback.
	audit   *auditRing
	auditMu sync.Mutex

	mu         sync.Mutex
	sessions   map[string]chan struct{}
	sessionCtl map[string]net.Conn // parked control channels, session id -> conn
	oauth      *oauthbridge.Bridge // OAuth loopback callback bridge (nil when disabled)
	// custodyRegistry holds the custody token sets (nil unless
	// -oauth-custody); MCP remotes with auth=custody: read it per session.
	custodyRegistry *oauthtokens.Registry
	limits          brokerLimits
	shutdown        chan<- struct{} // authenticated daemon shutdown request
}

func (br *broker) serve(ln net.Listener) {
	workers := new(sandboxsupervisor.BackgroundGroup)
	ctx, release, ok := workers.Acquire()
	if !ok {
		return
	}
	br.serveOwned(ctx, ln, workers.Start)
	release()
	workers.Close()
}

// serveOwned admits every accepted connection to the control-plane group.
// Closing that group cancels active sockets and joins their handlers.
func (br *broker) serveOwned(ctx context.Context, ln net.Listener, start func(func(context.Context)) bool) {
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
		if !start(func(ctx context.Context) {
			defer br.limits.releaseConnection()
			finished := make(chan struct{})
			watcherDone := make(chan struct{})
			go func() {
				defer close(watcherDone)
				select {
				case <-ctx.Done():
					_ = c.Close()
				case <-finished:
				}
			}()
			br.handle(c)
			close(finished)
			<-watcherDone
		}) {
			br.limits.releaseConnection()
			_ = c.Close()
			return
		}
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
	if req.Op == "sandbox.configure" {
		_ = c.SetWriteDeadline(time.Now().Add(controlproto.ConfigureTimeout))
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
	case "sandbox.configure":
		br.configureControl(c, req)
	case "netpolicy.set", "netpolicy.get":
		br.networkPolicyControl(c, req)
	case "policy.set":
		br.organizationPolicyControl(c, req)
	case "secret.set", "secret.remove":
		br.secretControl(c, req)
	case "mcp.remote.set", "mcp.remote.remove", "mcp.filesystem.set":
		br.mcpControl(c, req)
	case "audit.tail":
		lines, times := br.audit.snapshot()
		_ = json.NewEncoder(c).Encode(&controlproto.AuditResponse{Lines: lines, Times: times})
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

func (br *broker) organizationPolicyControl(c net.Conn, req controlproto.Request) {
	respond := func(resp controlproto.OrganizationPolicyResponse) { _ = json.NewEncoder(c).Encode(&resp) }
	if br.policyApply == nil {
		respond(controlproto.OrganizationPolicyResponse{Error: "live organization policy is unavailable"})
		return
	}
	if req.Policy == nil || req.Policy.Clear == (req.Policy.Snapshot != nil) {
		respond(controlproto.OrganizationPolicyResponse{Error: "supply exactly one of snapshot or clear=true"})
		return
	}
	if err := br.policyApply(req.Policy.Snapshot); err != nil {
		respond(controlproto.OrganizationPolicyResponse{Error: err.Error()})
		return
	}
	respond(controlproto.OrganizationPolicyResponse{OK: true})
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
	if present {
		// Control-socket sets are literal values (the dashboard path sends
		// the value over the local socket). Bound secrets must come from
		// -secret at start, which carries source specs with bindings.
		if len(req.Secret.Value.Raw()) >= controlproto.SecretsHandshakeMaxBytes {
			respond(controlproto.SecretResponse{Error: "secret value exceeds the handshake size limit"})
			return
		}
	}
	// Persist the binding/name transition first. If it fails before commit,
	// the live store remains unchanged; after commit, memory must follow disk
	// even when only the durability barrier failed.
	err := br.store.SetSecretName(req.Secret.Name, present)
	if err != nil && !atomicfile.Committed(err) {
		respond(controlproto.SecretResponse{Error: err.Error()})
		return
	}
	if present {
		br.secretStore.PutValue(req.Secret.Name, req.Secret.Value)
	} else {
		br.secretStore.Remove(req.Secret.Name)
	}
	if err != nil {
		respond(controlproto.SecretResponse{Error: "secret updated but configuration durability is uncertain: " + err.Error()})
		return
	}
	respond(controlproto.SecretResponse{OK: true})
}

// guestToolsPath prepends the staged helper directory to session PATHs
// once gantry-guest is installed, so `gantry-guest` and `credhelper` are
// callable bare.
func (br *broker) guestToolsPath() []string {
	if br.guestToolsReady.Load() {
		return []string{"/run/gantry/bin"}
	}
	return nil
}

// secretEnv renders the ambient injection set: literal values plus
// ambient (unbound) sources, resolved ONCE at spawn — env vars are a
// point-in-time snapshot by nature; bound secrets rotate live through the
// broker instead. A source that fails to resolve is dropped and logged
// (fail closed); the sandbox boots without that variable.
func (br *broker) secretEnv() []string {
	bindings := br.bindings()
	resolved := map[string]secret.Value{}
	bound := 0
	inject := func(name string) {
		if _, isBound := bindings[name]; isBound {
			// Bound secrets (NAME@host) are delivered through the credential
			// broker only — injecting them into every session's environment
			// would defeat the binding.
			bound++
			return
		}
		v, err := br.secretStore.Resolve(name)
		if err != nil {
			fmt.Printf("daemon: secret %s withheld from session env: %v\n", name, err)
			return
		}
		resolved[name] = v
	}
	for _, name := range br.secretStore.LiteralNames() {
		inject(name)
	}
	for name := range br.secretStore.Sources() {
		inject(name)
	}
	env := secret.Env(resolved)
	// With a bound secret held and the helper staged, point git at the
	// broker via ephemeral env config — no guest file is ever written.
	if (bound > 0 || br.cfg.OAuthCustodyEnabled()) && br.guestToolsReady.Load() {
		env = append(env,
			"GIT_CONFIG_COUNT=1",
			"GIT_CONFIG_KEY_0=credential.helper",
			"GIT_CONFIG_VALUE_0=/run/gantry/bin/credhelper",
		)
	}
	return env
}

// bindings maps clean secret name → host pattern. Two sources of truth,
// merged: the live Store (file sources carry their binding) and the
// persisted display names (eager env secrets carry their binding ONLY in
// the persisted spec — the handshake transports their values, not their
// bindings). A corrupt persisted entry is skipped; it can only widen a
// miss into NoBinding (fail closed).
func (br *broker) bindings() map[string]string {
	out := map[string]string{}
	if br.store != nil {
		for _, specName := range br.store.Snapshot().SecretNames {
			clean, binding, err := secret.SplitBinding(secret.HeadOf(specName))
			if err != nil || binding == "" {
				continue
			}
			out[clean] = binding
		}
	}
	for name, src := range br.secretStore.Sources() {
		if src.Binding != "" {
			out[name] = src.Binding
		}
	}
	return out
}

// resolveCredential implements credhelper.Resolver over the live store:
// the value resolves at REQUEST time, so a rotated file source is
// picked up mid-session. A source that stops resolving yields SourceError
// — the broker answers empty and audits the failure.
func (br *broker) resolveCredential(host string) (string, secret.Value, credhelper.Resolution) {
	if br.secretStore == nil {
		return br.resolveCustodyCredential(host)
	}
	bindings := br.bindings()
	names := make([]string, 0, len(bindings))
	for name := range bindings {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if !credhelper.HostMatches(bindings[name], host) {
			continue
		}
		v, err := br.secretStore.Resolve(name)
		if err != nil {
			return name, "", credhelper.SourceError
		}
		return name, v, credhelper.OK
	}
	return br.resolveCustodyCredential(host)
}

func (br *broker) mcpControl(c net.Conn, req controlproto.Request) {
	respond := func(resp controlproto.MCPResponse) { _ = json.NewEncoder(c).Encode(&resp) }
	if br.store == nil {
		respond(controlproto.MCPResponse{Error: "config store unavailable"})
		return
	}
	if req.MCP == nil {
		respond(controlproto.MCPResponse{Error: "MCP settings are required"})
		return
	}
	var err error
	switch req.Op {
	case "mcp.remote.set":
		_, err = br.store.SetMCPRemote(req.MCP.Spec, req.MCP.Replace)
	case "mcp.remote.remove":
		err = br.store.RemoveMCPRemote(req.MCP.Name)
	case "mcp.filesystem.set":
		err = br.store.SetMCPFilesystem(req.MCP.Root, req.MCP.User)
	}
	if err != nil && !atomicfile.Committed(err) {
		respond(controlproto.MCPResponse{Error: err.Error()})
		return
	}
	mutationErr := err
	marker := filepath.Join(br.dir, config.MCPRestartMarker)
	if err := atomicfile.WriteFileDurable(marker, []byte("restart required\n"), 0o600); err != nil {
		respond(controlproto.MCPResponse{Error: "MCP configuration updated but restart marker failed: " + err.Error()})
		return
	}
	if mutationErr != nil {
		respond(controlproto.MCPResponse{Error: "MCP configuration updated but durability is uncertain: " + mutationErr.Error()})
		return
	}
	respond(controlproto.MCPResponse{OK: true})
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
