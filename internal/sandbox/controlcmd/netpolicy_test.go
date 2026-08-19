package controlcmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ejpir/gantry/internal/netpol"
	"github.com/ejpir/gantry/internal/sandbox/control"
)

func TestPrintNetworkPolicyShow(t *testing.T) {
	policy, err := netpol.Parse([]byte(`{
		"default":"allow",
		"allowDomains":["api.github.com","api.openai.com"]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	entry := control.MakeNetworkPolicyEntry("/Users/test/.gantry/policy.json", false, policy, "active")
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
	printNetworkPolicyShow(&out, "sb", control.NetworkPolicyEntry{State: "active", AllowLocal: true, Description: ""})
	if !strings.Contains(out.String(), "allow") {
		t.Fatalf("AllowLocal=true must print allow, got:\n%s", out.String())
	}
	out.Reset()
	printNetworkPolicyShow(&out, "sb", control.NetworkPolicyEntry{State: "active", AllowLocal: false, Description: "policy: default allow, local net allowed, domains: x"})
	if !strings.Contains(out.String(), "deny") || strings.Contains(out.String(), "allow") {
		t.Fatalf("AllowLocal=false must print deny even when description says otherwise, got:\n%s", out.String())
	}
}
