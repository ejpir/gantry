package sandbox

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/ejpir/gantry/internal/netpol"
	"github.com/ejpir/gantry/internal/vnet"
)

func TestNetworkPolicyManagerAppliesAndPersists(t *testing.T) {
	dir := t.TempDir()
	store := newTestConfigStore(t, dir, RunConfig{Net: true})
	policyPath := filepath.Join(dir, "deny.json")
	if err := os.WriteFile(policyPath, []byte(`{
		"default":"deny",
		"rules":[{"action":"allow","cidr":"203.0.113.0/24","proto":"tcp","ports":"443"}]
	}`), 0o600); err != nil {
		t.Fatal(err)
	}
	resolvedPolicyPath, err := filepath.EvalSymlinks(policyPath)
	if err != nil {
		t.Fatal(err)
	}

	live := netpol.DefaultPolicy()
	manager := NewNetworkPolicyManager(store, newLocalBackend(&vnet.Stack{}, live), live)
	entry, err := manager.Set(policyPath, false)
	if err != nil {
		t.Fatal(err)
	}
	if entry.State != "active" || entry.Path != resolvedPolicyPath || !strings.Contains(entry.Description, "default deny") {
		t.Fatalf("active entry = %+v", entry)
	}
	if len(entry.Rules) == 0 {
		t.Fatal("active entry did not include effective rules")
	}
	if live.Allows([4]byte{8, 8, 8, 8}, 6, 443) {
		t.Fatal("live receiver did not switch to default-deny")
	}
	if !live.Allows([4]byte{203, 0, 113, 10}, 6, 443) {
		t.Fatal("live receiver did not apply the replacement allow rule")
	}
	if cfg := store.Snapshot(); cfg.NetPol != resolvedPolicyPath || cfg.AllowLN {
		t.Fatalf("persisted policy = path %q, allow-local %t", cfg.NetPol, cfg.AllowLN)
	}
	if err := os.Remove(policyPath); err != nil {
		t.Fatal(err)
	}
	shown, err := manager.Get()
	if err != nil {
		t.Fatal(err)
	}
	if shown.State != "active" || shown.Description != entry.Description {
		t.Fatalf("shown policy = %+v", shown)
	}

	entry, err = manager.Set("", true)
	if err != nil {
		t.Fatal(err)
	}
	if entry.Path != "" || !entry.AllowLocal || !live.Allows([4]byte{10, 0, 0, 1}, 6, 443) {
		t.Fatalf("default local override was not applied: %+v", entry)
	}
	if cfg := store.Snapshot(); cfg.NetPol != "" || !cfg.AllowLN {
		t.Fatalf("default policy was not persisted: %+v", cfg)
	}

	stopped := NewNetworkPolicyManager(store, nil, live)
	if _, err := stopped.Set(policyPath, false); err == nil || !strings.Contains(err.Error(), "running embedded netstack") {
		t.Fatalf("manager without a stack returned %v", err)
	}
	if cfg := store.Snapshot(); cfg.NetPol != "" || !cfg.AllowLN {
		t.Fatalf("failed live update changed persisted policy: %+v", cfg)
	}
}

func TestBrokerNetworkPolicyControl(t *testing.T) {
	dir := t.TempDir()
	store := newTestConfigStore(t, dir, RunConfig{Net: true})
	policyPath := filepath.Join(dir, "deny.json")
	if err := os.WriteFile(policyPath, []byte(`{"default":"deny"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	live := netpol.DefaultPolicy()
	br := &broker{
		netPolicy: NewNetworkPolicyManager(store, newLocalBackend(&vnet.Stack{}, live), live),
		sessions:  map[string]chan struct{}{},
	}
	request := `{"op":"netpolicy.set","id":"policy","net_policy":{"path":` + strconv.Quote(policyPath) + `}}` + "\n"
	if got := brokerPipe(t, br, request); !strings.Contains(got, `"ok":true`) || !strings.Contains(got, `"state":"active"`) || !strings.Contains(got, `"rules"`) {
		t.Fatalf("set response = %s", got)
	}
	if got := brokerPipe(t, br, `{"op":"netpolicy.get","id":"policy-show"}`+"\n"); !strings.Contains(got, `"ok":true`) || !strings.Contains(got, "default deny") {
		t.Fatalf("show response = %s", got)
	}
}

func TestPrintNetworkPolicyShow(t *testing.T) {
	policy, err := netpol.Parse([]byte(`{
		"default":"allow",
		"allowDomains":["api.github.com","api.openai.com"]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	entry := makeNetworkPolicyEntry("/Users/test/.gantry/policy.json", false, policy, "active")
	var output bytes.Buffer
	printNetworkPolicyShow(&output, "codex-dev", entry)
	got := output.String()
	for _, want := range []string{
		"SANDBOX", "STATE", "LOCAL NET", "POLICY",
		"codex-dev", "active", "deny", "/Users/test/.gantry/policy.json",
		"ACTION", "TARGET", "PROTO", "PORTS", "SOURCE",
		"DENY", "IPv6 and non-IPv4 traffic", "ALLOW", "api.openai.com",
		"local networks", "public internet", "default",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("pretty policy output missing %q:\n%s", want, got)
		}
	}
	if !strings.Contains(got, "\n\nACTION") {
		t.Fatalf("policy summary and rules are not separated:\n%s", got)
	}
	if strings.Contains(got, "network policy active:") {
		t.Fatalf("show still used mutation prose:\n%s", got)
	}
}

func TestPrintNetworkPolicyShowUsesAllowLocal(t *testing.T) {
	// regression: the local-net column must come from the authoritative
	// AllowLocal field — the older-daemon compat path leaves Description
	// empty, and description text is not state.
	var out strings.Builder
	printNetworkPolicyShow(&out, "sb", NetworkPolicyEntry{State: "active", AllowLocal: true, Description: ""})
	if !strings.Contains(out.String(), "allow") {
		t.Fatalf("AllowLocal=true must print allow, got:\n%s", out.String())
	}
	out.Reset()
	printNetworkPolicyShow(&out, "sb", NetworkPolicyEntry{State: "active", AllowLocal: false, Description: "policy: default allow, local net allowed, domains: x"})
	if !strings.Contains(out.String(), "deny") || strings.Contains(out.String(), "allow") {
		t.Fatalf("AllowLocal=false must print deny even when description says otherwise, got:\n%s", out.String())
	}
}
