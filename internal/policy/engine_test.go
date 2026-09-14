package policy_test

import (
	"context"
	"encoding/json"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ejpir/gantry/internal/netpol"
	"github.com/ejpir/gantry/internal/policy"
	"github.com/ejpir/gantry/internal/policy/policytest"
)

func TestAuthorizationAndNativeNetworkAgree(t *testing.T) {
	root := t.TempDir()
	profile := policy.Profile{
		Rules: []policy.Rule{
			{ID: "read", Effect: "allow", Action: policy.MountRead, Path: root},
			{ID: "secret", Effect: "deny", Action: policy.MountRead, Path: filepath.Join(root, "secret")},
			{ID: "tools", Effect: "allow", Action: policy.MCPCall, Server: "github", Tool: "read*"},
			{ID: "deny-tool", Effect: "deny", Action: policy.MCPCall, Server: "github", Tool: "read_secret"},
			{ID: "credential", Effect: "allow", Action: policy.CredentialUse, Host: "*.example.com"},
		},
		Network: policy.Network{
			Rules: []netpol.GuardRule{
				{ID: "https", Effect: "allow", CIDR: "0.0.0.0/0", Protocol: "tcp", Ports: []uint16{443}},
				{ID: "blocked", Effect: "deny", CIDR: "8.8.8.0/24", Protocol: "any"},
			},
			DNS: []string{"*.example.com"},
		},
	}
	var events []policy.Decision
	engine, err := policy.New(policytest.Signed(t, profile), func(d policy.Decision) { events = append(events, d) })
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		action   string
		resource policy.Resource
		allow    bool
	}{
		{policy.MountRead, policy.Resource{Path: filepath.Join(root, "code")}, true},
		{policy.MountRead, policy.Resource{Path: root}, false}, // parent contains denied subtree
		{policy.MountRead, policy.Resource{Path: root + "-other"}, false},
		{policy.MountWrite, policy.Resource{Path: filepath.Join(root, "code")}, false},
		{policy.MCPCall, policy.Resource{Server: "github", Tool: "read_issues"}, true},
		{policy.MCPCall, policy.Resource{Server: "github", Tool: "read_secret"}, false},
		{policy.MCPList, policy.Resource{Server: "github", Tool: "read_issues"}, false},
		{policy.CredentialUse, policy.Resource{Host: "API.EXAMPLE.COM."}, true},
		{policy.CredentialUse, policy.Resource{Host: "example.com.evil"}, false},
		{"unknown", policy.Resource{}, false},
	} {
		d := engine.Evaluate(context.Background(), tc.action, tc.resource)
		if (d.Effect == "allow") != tc.allow {
			t.Errorf("%s %+v: %+v", tc.action, tc.resource, d)
		}
		if d.Organization != "test-org" || d.Revision != "r1" || d.Profile != "dev" {
			t.Errorf("missing provenance: %+v", d)
		}
	}
	native, err := engine.ApplyNetwork(netpol.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"1.1.1.1", "8.8.8.8", "9.9.9.9"} {
		for _, protocol := range []string{"tcp", "udp", "icmp"} {
			for _, port := range []uint16{0, 53, 80, 443, 8443} {
				d := engine.Evaluate(context.Background(), policy.NetworkConnect, policy.Resource{IP: ip, Protocol: protocol, Port: port})
				p := map[string]uint8{"tcp": 6, "udp": 17, "icmp": 1}[protocol]
				if got := native.Allows([4]byte(net.ParseIP(ip).To4()), p, port); got != (d.Effect == "allow") {
					t.Errorf("native/OPA drift: %s %s:%d: %+v", protocol, ip, port, d)
				}
			}
		}
	}
	for _, host := range []string{"example.com", "api.example.com", "evil.example.com.evil", "EXAMPLE.COM."} {
		d := engine.Evaluate(context.Background(), policy.NetworkResolve, policy.Resource{Host: host})
		if native.DomainAllowed(host) != (d.Effect == "allow") {
			t.Errorf("DNS drift for %s: %+v", host, d)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if engine.Evaluate(ctx, policy.CredentialUse, policy.Resource{Host: "api.example.com"}).Effect != "deny" {
		t.Fatal("canceled query allowed")
	}
	raw, _ := json.Marshal(events)
	if strings.Contains(string(raw), root) || strings.Contains(string(raw), "api.example.com") {
		t.Fatal("audit leaked request resource")
	}
}

func TestBundleValidation(t *testing.T) {
	config := policytest.Signed(t, policy.Profile{})
	for name, mutate := range map[string]func(*policy.Config){
		"missing key":     func(c *policy.Config) { c.PublicKey = "" },
		"bad signature":   func(c *policy.Config) { c.Bundle[len(c.Bundle)/2] ^= 1 },
		"unknown profile": func(c *policy.Config) { c.Profile = "other" },
		"empty":           func(c *policy.Config) { c.Bundle = nil },
	} {
		t.Run(name, func(t *testing.T) {
			c := policy.CloneConfig(config)
			mutate(c)
			if _, err := policy.New(c, nil); err == nil {
				t.Fatal("accepted invalid bundle")
			}
		})
	}
	for name, profile := range map[string]policy.Profile{
		"ask":                {Rules: []policy.Rule{{ID: "r", Action: policy.MCPCall, Effect: "ask", Server: "*", Tool: "*"}}},
		"unknown action":     {Rules: []policy.Rule{{ID: "r", Action: "mcp.anything", Effect: "allow", Server: "*", Tool: "*"}}},
		"misplaced selector": {Rules: []policy.Rule{{ID: "r", Action: policy.CredentialUse, Effect: "allow", Host: "*", Server: "*"}}},
		"noncanonical CIDR":  {Network: policy.Network{Rules: []netpol.GuardRule{{ID: "n", Effect: "allow", CIDR: "10.0.0.1/8", Protocol: "tcp"}}}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := policy.New(policytest.Signed(t, profile), nil); err == nil {
				t.Fatal("accepted unsupported schema")
			}
		})
	}
	expired := policytest.Document(t, policy.Document{Version: 1, Organization: "test-org", Revision: "r1", ExpiresAt: time.Now().Add(-time.Second), Profiles: map[string]policy.Profile{"dev": {}}})
	if _, err := policy.New(expired, nil); err == nil {
		t.Fatal("accepted expired snapshot")
	}
	unknown := policytest.Data(t, map[string]any{"gantry": map[string]any{"version": 1, "unknown": true}})
	if _, err := policy.New(unknown, nil); err == nil {
		t.Fatal("accepted unknown field")
	}
}
