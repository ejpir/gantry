package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ejpir/gantry/internal/netpol"
	"github.com/ejpir/gantry/internal/policy"
	"github.com/open-policy-agent/opa/v1/bundle"
)

const argumentCanary = "OPA-ARGUMENT-MUST-NOT-APPEAR-IN-AUDIT"

type fixtures struct {
	root, allowed, forbidden, extraAllowed                 string
	publicKey, wrongKey, good, tampered, unsigned, expired string
	key                                                    *rsa.PrivateKey
	profile                                                policy.Profile
}

func newFixtures(root string, allowPort, denyPort uint16) (*fixtures, error) {
	f := &fixtures{root: root, allowed: filepath.Join(root, "shares", "allowed"), forbidden: filepath.Join(root, "shares", "forbidden"), extraAllowed: filepath.Join(root, "shares", "extra")}
	for _, dir := range []string{f.allowed, f.forbidden, f.extraAllowed} {
		if err := writeFile(filepath.Join(dir, "marker"), []byte("OPA-SHARE-OK\n"), 0644); err != nil {
			return nil, err
		}
	}
	var err error
	f.key, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	f.publicKey = filepath.Join(root, "public.pem")
	if err := writeFile(f.publicKey, publicPEM(f.key), 0600); err != nil {
		return nil, err
	}
	wrong, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	f.wrongKey = filepath.Join(root, "wrong.pem")
	if err := writeFile(f.wrongKey, publicPEM(wrong), 0600); err != nil {
		return nil, err
	}
	f.profile = policy.Profile{
		Rules: []policy.Rule{
			{ID: "mount", Effect: "allow", Action: policy.MountRead, Path: f.allowed},
			{ID: "extra-mount", Effect: "allow", Action: policy.MountRead, Path: f.extraAllowed},
			{ID: "connect", Effect: "allow", Action: policy.MCPConnect, Server: "*"},
			{ID: "list", Effect: "allow", Action: policy.MCPList, Server: "mock", Tool: "*"},
			{ID: "hide", Effect: "deny", Action: policy.MCPList, Server: "mock", Tool: "hidden"},
			{ID: "call", Effect: "allow", Action: policy.MCPCall, Server: "mock", Tool: "read"},
			{ID: "blocked-call", Effect: "allow", Action: policy.MCPCall, Server: "blocked", Tool: "read"},
			{ID: "credential", Effect: "allow", Action: policy.CredentialUse, Host: "git.allowed.test"},
		},
		Network: policy.Network{
			Rules: []netpol.GuardRule{
				{ID: "guest-http", Effect: "allow", CIDR: "192.168.127.254/32", Protocol: "tcp", Ports: []uint16{allowPort, denyPort}},
				{ID: "mcp-http", Effect: "allow", CIDR: "127.0.0.1/32", Protocol: "tcp", Ports: []uint16{allowPort, denyPort}},
				{ID: "deny-port", Effect: "deny", CIDR: "0.0.0.0/0", Protocol: "tcp", Ports: []uint16{denyPort}},
			},
			DNS: []string{"gateway.containers.internal", "git.allowed.test", "git.denied.test", "127.0.0.1"},
		},
	}
	f.good, err = f.sign("good", "fixture-1", time.Now().Add(time.Hour), f.profile)
	if err != nil {
		return nil, err
	}
	f.expired, err = f.sign("expired", "expired-1", time.Now().Add(-time.Minute), f.profile)
	if err != nil {
		return nil, err
	}
	// Repack valid gzip/tar/JSON with changed data but the original signature.
	// A random compressed-byte corruption would test framing, not authenticity.
	raw, err := os.ReadFile(f.good)
	if err != nil {
		return nil, err
	}
	verification := bundle.NewVerificationConfig(map[string]*bundle.KeyConfig{
		"gantry": {Key: string(publicPEM(f.key)), Algorithm: "RS256"},
	}, "gantry", "", nil)
	parsed, err := bundle.NewReader(bytes.NewReader(raw)).WithBundleVerificationConfig(verification).Read()
	if err != nil {
		return nil, err
	}
	parsed.Data["gantry"].(map[string]any)["organization"] = "forged-org"
	f.tampered = filepath.Join(root, "tampered.tar.gz")
	if err := writeBundle(f.tampered, parsed); err != nil {
		return nil, err
	}
	parsed.Signatures = bundle.SignaturesConfig{}
	f.unsigned = filepath.Join(root, "unsigned.tar.gz")
	if err := writeBundle(f.unsigned, parsed); err != nil {
		return nil, err
	}
	return f, nil
}
func publicPEM(key *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&key.PublicKey)})
}
func (f *fixtures) sign(name, revision string, expires time.Time, profile policy.Profile) (string, error) {
	data := map[string]any{"gantry": policy.Document{Version: 1, Organization: "e2e-org", Revision: revision, ExpiresAt: expires.UTC(), Profiles: map[string]policy.Profile{"dev": profile}}}
	raw, err := json.Marshal(data)
	if err != nil {
		return "", err
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return "", err
	}
	b := bundle.Bundle{Data: decoded, Manifest: bundle.Manifest{Roots: &[]string{""}}}
	private := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(f.key)})
	if err := b.GenerateSignature(bundle.NewSigningConfig(string(private), "RS256", ""), "gantry", false); err != nil {
		return "", err
	}
	path := filepath.Join(f.root, name+".tar.gz")
	return path, writeBundle(path, b)
}
func writeBundle(path string, b bundle.Bundle) error {
	var buffer bytes.Buffer
	if err := bundle.NewWriter(&buffer).Write(b); err != nil {
		return err
	}
	return writeFile(path, buffer.Bytes(), 0600)
}
func (f *fixtures) flags(path, key string) []string {
	return []string{"-org-policy", path, "-org-policy-key", key, "-policy-profile", "dev"}
}
func (f *fixtures) policyArgs(op, path string) []string {
	return []string{"policy", op, "-bundle", path, "-key", f.publicKey, "-profile", "dev"}
}

// endpoint is a loopback-only HTTP/MCP upstream. Counters prove denied guest
// connections/tool invocations never arrive; a successful positive control
// prevents an unavailable server from masquerading as effective enforcement.
type endpoint struct {
	*httptest.Server
	marker      string
	connections atomic.Int64
	mu          sync.Mutex
	calls       map[string]int
}

func newEndpoint(marker string) *endpoint {
	e := &endpoint{marker: marker, calls: map[string]int{}}
	e.Server = httptest.NewUnstartedServer(http.HandlerFunc(e.serve))
	e.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			e.connections.Add(1)
		}
	}
	e.Start()
	return e
}
func (e *endpoint) port() uint16 {
	_, port, _ := net.SplitHostPort(e.Listener.Addr().String())
	n, _ := strconv.ParseUint(port, 10, 16)
	return uint16(n)
}
func (e *endpoint) guestURL() string {
	return fmt.Sprintf("http://192.168.127.254:%d/egress", e.port())
}
func (e *endpoint) callCount(tool string) int { e.mu.Lock(); defer e.mu.Unlock(); return e.calls[tool] }
func (e *endpoint) serve(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/mcp" {
		_, _ = fmt.Fprintln(w, e.marker)
		return
	}
	var request struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
		Params struct {
			Name string `json:"name"`
		} `json:"params"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&request); err != nil {
		http.Error(w, "bad request", 400)
		return
	}
	if len(request.ID) == 0 {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	var value any = map[string]any{}
	switch request.Method {
	case "initialize":
		value = map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{"tools": map[string]any{}}, "serverInfo": map[string]any{"name": "policy-fixture", "version": "1"}}
	case "tools/list":
		var tools []map[string]any
		for _, name := range []string{"read", "listed", "hidden"} {
			tools = append(tools, map[string]any{"name": name, "inputSchema": map[string]any{"type": "object"}})
		}
		value = map[string]any{"tools": tools}
	case "tools/call":
		e.mu.Lock()
		e.calls[request.Params.Name]++
		e.mu.Unlock()
		value = map[string]any{"content": []map[string]any{{"type": "text", "text": "OPA-MCP-CALL-OK"}}}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": request.ID, "result": value})
}
func (e *endpoint) healthy(ctxTimeout time.Duration) error {
	client := &http.Client{Timeout: ctxTimeout, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}}
	defer client.CloseIdleConnections()
	response, err := client.Get(e.URL + "/health")
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	var data bytes.Buffer
	_, err = data.ReadFrom(response.Body)
	if err != nil {
		return err
	}
	if response.StatusCode != 200 || !strings.Contains(data.String(), e.marker) {
		return fmt.Errorf("fixture health check failed")
	}
	return nil
}
