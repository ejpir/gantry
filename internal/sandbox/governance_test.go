package sandbox

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/ejpir/gantry/internal/netpol"
	"github.com/ejpir/gantry/internal/policy"
	"github.com/ejpir/gantry/internal/policy/policytest"
	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/credhelper"
	"github.com/ejpir/gantry/internal/secret"
)

func TestOrganizationCredentialAndMCPDialGates(t *testing.T) {
	engine, err := policy.New(policytest.Signed(t, policy.Profile{
		Rules:   []policy.Rule{{ID: "credential", Effect: "allow", Action: policy.CredentialUse, Host: "github.com"}},
		Network: policy.Network{DNS: []string{"github.com"}, Rules: []netpol.GuardRule{{ID: "endpoint", Effect: "allow", CIDR: "1.1.1.1/32", Protocol: "tcp", Ports: []uint16{443}}}},
	}), nil)
	if err != nil {
		t.Fatal(err)
	}
	d := &daemonSupervisor{governance: policy.NewController(engine), control: controlPlane{broker: &broker{domainAllowed: func(string) bool { return true }}}}
	resolved := 0
	broker := credhelper.New(func(string) (string, secret.Value, credhelper.Resolution) {
		resolved++
		return "TOKEN", secret.Value("test-secret"), credhelper.OK
	}, d.credentialAllowed, nil)
	if response := broker.Decide(credhelper.Request{Host: "evil.example"}); response.Password != "" || resolved != 0 {
		t.Fatal("denied credential source resolved")
	}
	if !d.credentialAllowed("github.com") {
		t.Fatal("approved credential rejected")
	}
	for _, tc := range []struct {
		host, ip, port string
		allow          bool
	}{
		{"github.com", "1.1.1.1", "443", true},
		{"github.com", "8.8.8.8", "443", false},
		{"github.com", "1.1.1.1", "80", false},
		{"evil.example", "1.1.1.1", "443", false},
		{"github.com", "2606:4700:4700::1111", "443", false},
	} {
		err := d.authorizeMCPDial(context.Background(), tc.host, net.ParseIP(tc.ip), tc.port)
		if (err == nil) != tc.allow {
			t.Errorf("%+v: %v", tc, err)
		}
	}
}

func TestMCPAuthorizationClosureFollowsLiveController(t *testing.T) {
	controller := policy.NewController(nil)
	d := &daemonSupervisor{governance: controller, control: controlPlane{broker: &broker{}}, cfg: config.RunConfig{}}
	servers, err := d.resolveMCPServers()
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) == 0 || servers[0].Authorize == nil {
		t.Fatal("unmanaged MCP server did not retain a live authorization closure")
	}
	if err := servers[0].Authorize(context.Background(), policy.MCPCall, "read_file"); err != nil {
		t.Fatal(err)
	}
	engine, err := policy.New(policytest.Signed(t, policy.Profile{}), nil)
	if err != nil {
		t.Fatal(err)
	}
	controller.Store(engine)
	if err := servers[0].Authorize(context.Background(), policy.MCPCall, "read_file"); err == nil {
		t.Fatal("existing MCP closure did not observe the live policy")
	}
}

func TestOrganizationLaunchPinsBundleAndRejectsUnsupportedCustody(t *testing.T) {
	original := policytest.Signed(t, policy.Profile{})
	dir := t.TempDir()
	bundlePath, keyPath := filepath.Join(dir, "bundle.tar.gz"), filepath.Join(dir, "public.pem")
	if err := os.WriteFile(bundlePath, original.Bundle, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte(original.PublicKey), 0600); err != nil {
		t.Fatal(err)
	}
	r := runResolver{options: config.RunOptions{OrgPolicy: bundlePath, OrgPolicyKey: keyPath, PolicyProfile: "dev"}}
	if err := r.resolveOrganizationPolicy(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte("replacement key"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(bundlePath); err != nil {
		t.Fatal(err)
	}
	if _, err := policy.New(r.cfg.OrgPolicy, nil); err != nil {
		t.Fatalf("source mutation changed snapshot: %v", err)
	}
	enabled := true
	d := daemonSupervisor{cfg: config.RunConfig{OrgPolicy: r.cfg.OrgPolicy, OAuthCustody: &enabled}}
	if err := d.loadOrganizationPolicy(); err == nil {
		t.Fatal("ungoverned OAuth custody path accepted")
	}
}
