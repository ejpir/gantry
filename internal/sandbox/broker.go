package sandbox

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

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
	cfg        RunConfig
	dir        string
	rpc        *ttrpc.Client
	streamSock string
	// streamDial replaces the streamSock unix dial in the split-VMM
	// topology (streams cross the worker bridge).
	streamDial func() (net.Conn, error)
	store      *ConfigStore
	shares     *ShareManager
	ports      *PortManager
	netPolicy  *NetworkPolicyManager
	secrets    map[string]secret.Value // memory only, VM lifetime — never serialized

	mu         sync.Mutex
	sessions   map[string]chan struct{}
	sessionCtl map[string]net.Conn // parked control channels, session id -> conn
	oauth      *oauthBridge        // OAuth loopback callback bridge (nil when disabled)
	limits     brokerLimits
	shutdown   chan<- struct{} // authenticated daemon shutdown request
}

type brokerRequest struct {
	Op        string                      `json:"op"` // "session" | "sessionctl" | "kill" | "share.*" | "port.*" | "resources.set"
	ID        string                      `json:"id"`
	V         int                         `json:"v,omitempty"` // sessionctl: sessionProtocolVersion
	Args      []string                    `json:"args,omitempty"`
	Cols      uint32                      `json:"cols,omitempty"`
	Rows      uint32                      `json:"rows,omitempty"`
	Terminal  bool                        `json:"terminal,omitempty"`
	Share     *brokerShareRequest         `json:"share,omitempty"`
	Port      *brokerPortRequest          `json:"port,omitempty"`
	Resources *brokerResourceRequest      `json:"resources,omitempty"`
	NetPolicy *brokerNetworkPolicyRequest `json:"net_policy,omitempty"`
}

type brokerResourceRequest struct {
	MemMB uint `json:"mem_mb"`
	VCPUs int  `json:"vcpus"`
}

type brokerResourceResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

type brokerShareRequest struct {
	Spec       string `json:"spec,omitempty"`
	Tag        string `json:"tag,omitempty"`
	Persistent bool   `json:"persistent"`
	Replace    bool   `json:"replace,omitempty"`
	Force      bool   `json:"force,omitempty"`
}

type brokerShareResponse struct {
	OK         bool           `json:"ok"`
	Error      string         `json:"error,omitempty"`
	Generation uint64         `json:"generation,omitempty"`
	Entry      *shares.Entry  `json:"entry,omitempty"`
	Shares     []shares.Entry `json:"shares,omitempty"`
}

type brokerPortRequest struct {
	Spec       string `json:"spec"`
	Persistent bool   `json:"persistent"`
}

type brokerPortResponse struct {
	OK    bool        `json:"ok"`
	Error string      `json:"error,omitempty"`
	Entry *PortEntry  `json:"entry,omitempty"`
	Ports []PortEntry `json:"ports,omitempty"`
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
		if !peerSameUser(c) {
			fmt.Fprintln(os.Stderr, "daemon: rejected ctl.sock connection from a foreign UID")
			_ = c.Close()
			continue
		}
		if !br.limits.acquireConnection() {
			_ = c.SetWriteDeadline(time.Now().Add(controlOverloadTimeout))
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
	_ = c.SetReadDeadline(time.Now().Add(controlHandshakeTimeout))
	r := bufio.NewReader(c)
	line, err := readBoundedLine(r, controlMaxRequestBytes)
	_ = c.SetReadDeadline(time.Time{})
	if err != nil {
		if errors.Is(err, errControlFrameTooLarge) {
			_ = c.SetWriteDeadline(time.Now().Add(controlOverloadTimeout))
			_, _ = fmt.Fprintln(c, `{"error":"control request too large"}`)
		}
		return
	}
	_ = c.SetWriteDeadline(time.Now().Add(controlCallTimeout))
	var req brokerRequest
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
	case "session":
		br.session(c, r, req)
	case "sessionctl":
		br.sessionctl(c, r, req)
	default:
		_, _ = fmt.Fprintln(c, `{"error":"unknown op"}`)
	}
}

func (br *broker) resourceControl(c net.Conn, req brokerRequest) {
	respond := func(resp brokerResourceResponse) {
		_ = json.NewEncoder(c).Encode(&resp)
	}
	if br.store == nil {
		respond(brokerResourceResponse{Error: "config store unavailable"})
		return
	}
	if req.Resources == nil {
		respond(brokerResourceResponse{Error: "resource settings are required"})
		return
	}
	if err := br.store.SetResources(req.Resources.MemMB, req.Resources.VCPUs); err != nil {
		respond(brokerResourceResponse{Error: err.Error()})
		return
	}
	respond(brokerResourceResponse{OK: true})
}

func (br *broker) networkPolicyControl(c net.Conn, req brokerRequest) {
	respond := func(resp brokerNetworkPolicyResponse) {
		_ = json.NewEncoder(c).Encode(&resp)
	}
	if br.netPolicy == nil {
		respond(brokerNetworkPolicyResponse{Error: "network policy manager unavailable"})
		return
	}
	var entry NetworkPolicyEntry
	var err error
	if req.Op == "netpolicy.set" {
		if req.NetPolicy == nil {
			respond(brokerNetworkPolicyResponse{Error: "network policy settings are required"})
			return
		}
		entry, err = br.netPolicy.Set(req.NetPolicy.Path, req.NetPolicy.AllowLocal)
	} else {
		entry, err = br.netPolicy.Get()
	}
	if err != nil {
		respond(brokerNetworkPolicyResponse{Error: err.Error()})
		return
	}
	respond(brokerNetworkPolicyResponse{OK: true, Policy: &entry})
}

func (br *broker) shareControl(c net.Conn, req brokerRequest) {
	respond := func(resp brokerShareResponse) {
		_ = json.NewEncoder(c).Encode(&resp)
	}
	spec := brokerShareRequest{Persistent: true}
	if req.Share != nil {
		spec = *req.Share
	}
	var entry shares.Entry
	var err error
	if req.Op == "share.configure" {
		if br.shares == nil {
			respond(brokerShareResponse{Error: "share manager unavailable"})
			return
		}
		configured, configureErr := br.shares.ConfigureRestart(spec.Spec, spec.Replace)
		if configureErr != nil {
			respond(brokerShareResponse{Error: configureErr.Error()})
			return
		}
		entry = shares.Entry{
			Tag: configured.Tag, Path: configured.Path, RO: configured.RO,
			UID: configured.UID, GID: configured.GID,
			VMPath:  shares.HubVMPath + "/" + configured.Tag,
			CtrPath: configuredShareTarget(configured), State: "restart",
		}
		respond(brokerShareResponse{OK: true, Entry: &entry})
		return
	}
	if br.shares == nil {
		respond(brokerShareResponse{Error: "share manager unavailable"})
		return
	}
	switch req.Op {
	case "share.add":
		entry, err = br.shares.Add(spec.Spec, spec.Persistent, spec.Replace)
	case "share.remove":
		entry, err = br.shares.Remove(spec.Tag, spec.Persistent, spec.Force)
	case "share.list":
		respond(brokerShareResponse{OK: true, Generation: br.shares.Generation(), Shares: br.shares.Entries()})
		return
	}
	if err != nil {
		respond(brokerShareResponse{Error: err.Error(), Generation: br.shares.Generation()})
		return
	}
	respond(brokerShareResponse{OK: true, Generation: br.shares.Generation(), Entry: &entry})
}

func (br *broker) portControl(c net.Conn, req brokerRequest) {
	respond := func(resp brokerPortResponse) {
		_ = json.NewEncoder(c).Encode(&resp)
	}
	if br.ports == nil {
		respond(brokerPortResponse{Error: "port manager unavailable"})
		return
	}
	spec := brokerPortRequest{Persistent: true}
	if req.Port != nil {
		spec = *req.Port
	}
	var entry PortEntry
	var err error
	switch req.Op {
	case "port.publish":
		entry, err = br.ports.Publish(spec.Spec, spec.Persistent)
	case "port.unpublish":
		entry, err = br.ports.Unpublish(spec.Spec, spec.Persistent)
	case "port.list":
		ports, lerr := br.ports.List()
		if lerr != nil {
			respond(brokerPortResponse{Error: lerr.Error()})
			return
		}
		respond(brokerPortResponse{OK: true, Ports: ports})
		return
	}
	if err != nil {
		respond(brokerPortResponse{Error: err.Error()})
		return
	}
	respond(brokerPortResponse{OK: true, Entry: &entry})
}
