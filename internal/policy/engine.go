package policy

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"time"

	"github.com/ejpir/gantry/internal/netpol"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
)

const (
	MountRead      = "mount.read"
	MountWrite     = "mount.write"
	MCPList        = "mcp.tools.list"
	MCPCall        = "mcp.tools.call"
	MCPConnect     = "mcp.connect"
	CredentialUse  = "credential.use"
	NetworkConnect = "network.connect"
	NetworkResolve = "network.resolve"
)

//go:embed authz.rego
var module string

type Resource struct {
	Path     string `json:"path"`
	Server   string `json:"server"`
	Tool     string `json:"tool"`
	Host     string `json:"host"`
	IP       string `json:"ip"`
	Protocol string `json:"protocol"`
	Port     uint16 `json:"port"`
}

// Decision is safe to audit: no request arguments, results or credential data.
// Identity and revision are supplied by the wrapper, never by guest input.
type Decision struct {
	Effect       string   `json:"effect"`
	Reason       string   `json:"reason"`
	Rules        []string `json:"rules"`
	Action       string   `json:"action"`
	Organization string   `json:"organization"`
	Revision     string   `json:"revision"`
	Profile      string   `json:"profile"`
}

// Engine is one immutable snapshot. Calls are concurrent-safe; the optional
// audit callback must also be concurrent-safe. No file or network I/O occurs
// during evaluation. Policy expiry is checked independently of Rego results.
type Engine struct {
	query                           rego.PreparedEvalQuery
	guard                           netpol.GuardSpec
	expires                         time.Time
	organization, revision, profile string
	audit                           func(Decision)
}

func New(config *Config, audit func(Decision)) (*Engine, error) {
	if config == nil {
		return nil, nil
	}
	document, profile, err := verify(config)
	if err != nil {
		return nil, err
	}
	// Normalize platform path separators once, outside Rego. Paths originate
	// from host-validated bundle rules or pinned export identities.
	for i := range profile.Rules {
		profile.Rules[i].Path = filepath.ToSlash(profile.Rules[i].Path)
	}
	raw, err := json.Marshal(map[string]any{"meta": map[string]any{
		"organization": document.Organization, "revision": document.Revision, "expires_at": document.ExpiresAt,
	}, "profile": profile})
	if err != nil {
		return nil, err
	}
	var data map[string]any
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, err
	}
	store := inmem.NewFromObject(data)
	// An explicit capabilities allowlist makes accidental future additions of
	// http.send, DNS lookup, time, or other side-effecting builtins fail compile.
	caps := ast.CapabilitiesForThisVersion()
	allowed := map[string]bool{
		"eq": true, "equal": true, "neq": true, "gt": true,
		"count": true, "sort": true, "internal.member_2": true,
		"startswith": true, "endswith": true, "concat": true,
		"trim_suffix": true, "trim_prefix": true, "net.cidr_contains": true,
	}
	builtins := caps.Builtins[:0]
	for _, builtin := range caps.Builtins {
		if allowed[builtin.Name] {
			builtins = append(builtins, builtin)
		}
	}
	caps.Builtins = builtins
	caps.AllowNet = []string{}
	prepare := func(query string) (rego.PreparedEvalQuery, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return rego.New(rego.Query(query), rego.Module("gantry.rego", module), rego.Store(store), rego.Capabilities(caps), rego.StrictBuiltinErrors(true)).PrepareForEval(ctx)
	}
	query, err := prepare("data.gantry.decision")
	if err != nil {
		return nil, fmt.Errorf("compile organization policy: %w", err)
	}
	plan, err := prepare("data.gantry.network_plan")
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result, err := plan.Eval(ctx)
	if err != nil || len(result) != 1 || len(result[0].Expressions) != 1 {
		return nil, fmt.Errorf("organization network plan is undefined or invalid: %v", err)
	}
	raw, err = json.Marshal(result[0].Expressions[0].Value)
	if err != nil {
		return nil, err
	}
	var guard netpol.GuardSpec
	if err := decodeStrict(raw, &guard); err != nil {
		return nil, err
	}
	if err := netpol.ValidateGuard(guard); err != nil {
		return nil, err
	}
	return &Engine{query: query, guard: guard, expires: document.ExpiresAt, organization: document.Organization, revision: document.Revision, profile: config.Profile, audit: audit}, nil
}

type SnapshotInfo struct {
	Organization string    `json:"organization"`
	Revision     string    `json:"revision"`
	Profile      string    `json:"profile"`
	ExpiresAt    time.Time `json:"expires_at"`
}

func (e *Engine) Info() SnapshotInfo {
	if e == nil {
		return SnapshotInfo{}
	}
	return SnapshotInfo{Organization: e.organization, Revision: e.revision, Profile: e.profile, ExpiresAt: e.expires}
}

func (e *Engine) ExpiresAt() time.Time {
	if e == nil {
		return time.Time{}
	}
	return e.expires
}

func (e *Engine) ApplyNetwork(local *netpol.Policy) (*netpol.Policy, error) {
	if e == nil {
		return local, nil
	}
	return netpol.WithGuard(local, e.guard)
}

func (e *Engine) Evaluate(ctx context.Context, action string, resource Resource) Decision {
	decision := Decision{Effect: "deny", Reason: "evaluation_error", Rules: []string{}, Action: action}
	if e == nil {
		decision.Effect, decision.Reason = "allow", "unmanaged"
		return decision
	}
	decision.Organization, decision.Revision, decision.Profile = e.organization, e.revision, e.profile
	defer func() {
		if e.audit != nil {
			e.audit(decision)
		}
	}()
	if !time.Now().Before(e.expires) {
		decision.Reason = "policy_expired"
		return decision
	}
	resource.Path = filepath.ToSlash(resource.Path)
	resource.Host = strings.ToLower(strings.TrimSuffix(resource.Host, "."))
	if !validResource(action, resource) {
		decision.Reason = "invalid_request"
		return decision
	}
	ctx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	result, err := e.query.Eval(ctx, rego.EvalInput(map[string]any{"action": action, "resource": resource}))
	if err != nil || len(result) != 1 || len(result[0].Expressions) != 1 {
		return decision
	}
	raw, err := json.Marshal(result[0].Expressions[0].Value)
	if err != nil {
		return decision
	}
	var output struct {
		Effect string   `json:"effect"`
		Reason string   `json:"reason"`
		Rules  []string `json:"rules"`
	}
	if err := decodeStrict(raw, &output); err != nil || (output.Effect != "allow" && output.Effect != "deny") || !validID(output.Reason) || len(output.Rules) > 256 {
		return decision
	}
	// A cancellation/expiry racing evaluation cannot publish an allow.
	if ctx.Err() != nil {
		return decision
	}
	if !time.Now().Before(e.expires) {
		decision.Reason = "policy_expired"
		return decision
	}
	decision.Effect, decision.Reason, decision.Rules = output.Effect, output.Reason, output.Rules
	return decision
}

func (e *Engine) Authorize(ctx context.Context, action string, resource Resource) error {
	decision := e.Evaluate(ctx, action, resource)
	if decision.Effect == "allow" {
		return nil
	}
	return fmt.Errorf("organization policy denied %s: %s (org=%s revision=%s)", action, decision.Reason, decision.Organization, decision.Revision)
}

func validResource(action string, r Resource) bool {
	if len(r.Path) > 4096 || len(r.Host) > 253 || len(r.Server) > 128 || len(r.Tool) > 256 || len(r.IP) > 64 || len(r.Protocol) > 8 {
		return false
	}
	switch action {
	case MountRead, MountWrite:
		return filepath.IsAbs(r.Path) && filepath.ToSlash(filepath.Clean(r.Path)) == r.Path
	case MCPList, MCPCall:
		return r.Server != "" && r.Tool != ""
	case MCPConnect:
		return r.Server != ""
	case CredentialUse, NetworkResolve:
		return !strings.Contains(r.Host, "*") && netpol.ValidGuardDomain(r.Host)
	case NetworkConnect:
		ip, err := netip.ParseAddr(r.IP)
		return err == nil && ip.Is4() && (r.Protocol == "tcp" || r.Protocol == "udp" || r.Protocol == "icmp")
	default:
		return false
	}
}
