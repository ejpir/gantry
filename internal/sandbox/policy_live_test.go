package sandbox

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ejpir/gantry/internal/netpol"
	"github.com/ejpir/gantry/internal/policy"
	"github.com/ejpir/gantry/internal/policy/policytest"
	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/control"
	"github.com/ejpir/gantry/internal/vnet"
)

type livePolicyNetworkBackend struct {
	policy   *netpol.Policy
	updates  []*netpol.Policy
	fail     bool
	calls    int
	failCall int
}

func (*livePolicyNetworkBackend) Publish(string, string, string) error { return nil }
func (*livePolicyNetworkBackend) Unpublish(string, string) error       { return nil }
func (*livePolicyNetworkBackend) Forwards() ([]vnet.Forward, error)    { return nil, nil }
func (backend *livePolicyNetworkBackend) SetPolicy(next *netpol.Policy) error {
	backend.calls++
	if backend.fail || backend.calls == backend.failCall {
		backend.fail = false
		return errors.New("network update failed")
	}
	cloned, err := control.ClonePolicy(next)
	if err == nil {
		backend.policy = cloned
		backend.updates = append(backend.updates, cloned)
	}
	return err
}

func newLivePolicyDaemon(t *testing.T) (*daemonSupervisor, *livePolicyNetworkBackend) {
	t.Helper()
	dir := t.TempDir()
	cfg := config.RunConfig{MemMB: 512, VCPUs: 1, Net: true}
	if err := config.WriteSandboxConfig(dir, cfg); err != nil {
		t.Fatal(err)
	}
	store, err := config.LoadConfigStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	local := netpol.DefaultPolicy()
	backend := &livePolicyNetworkBackend{policy: local}
	transactions := control.NewNetworkTransactionCoordinator()
	networkManager := control.NewNetworkPolicyManagerWithCoordinator(store, backend, local, transactions)
	d := &daemonSupervisor{
		dir: dir, cfg: cfg,
		governance: policy.NewController(nil), policyChanged: make(chan struct{}, 1),
	}
	d.host.SetConfig(store)
	d.host.SetAudit(&auditRing{})
	network := &Network{Policy: local, Backend: backend}
	d.host.SetNetwork(networkView{network: network}, network.CloseBackend, network.Close)
	d.host.SetTransactions(transactions)
	d.control.SetBroker(&broker{netPolicy: networkManager})
	d.control.SetShutdown(make(chan struct{}, 1))
	return d, backend
}

func TestLiveOrganizationPolicyUpdatesNetworkCredentialsPersistenceAndExpiry(t *testing.T) {
	d, backend := newLivePolicyDaemon(t)
	candidate := policytest.Signed(t, policy.Profile{
		Rules: []policy.Rule{{ID: "credential", Effect: "allow", Action: policy.CredentialUse, Host: "allowed.example"}},
		Network: policy.Network{DNS: []string{"allowed.example"}, Rules: []netpol.GuardRule{{
			ID: "web", Effect: "allow", CIDR: "203.0.113.10/32", Protocol: "tcp", Ports: []uint16{443},
		}}},
	})
	if err := d.applyOrganizationPolicy(candidate); err != nil {
		t.Fatal(err)
	}
	if err := d.governance.Authorize(context.Background(), policy.CredentialUse, policy.Resource{Host: "allowed.example"}); err != nil {
		t.Fatal(err)
	}
	if err := d.governance.Authorize(context.Background(), policy.CredentialUse, policy.Resource{Host: "denied.example"}); err == nil {
		t.Fatal("new credential policy was not activated")
	}
	if backend.policy.DomainAllowed("other.example") || !backend.policy.DomainAllowed("allowed.example") {
		t.Fatal("new organization network guard was not activated")
	}
	if len(backend.updates) < 2 || backend.updates[0].Allows([4]byte{8, 8, 8, 8}, 6, 443) {
		t.Fatal("live update did not enter a fail-closed network barrier")
	}
	saved, err := config.ReadSandboxConfig(d.dir)
	if err != nil {
		t.Fatal(err)
	}
	if !sameLiveOrganizationPolicy(saved.OrgPolicy, candidate) {
		t.Fatal("new policy snapshot was not persisted")
	}
	select {
	case <-d.policyChanged:
	default:
		t.Fatal("expiry supervisor was not notified")
	}

	if err := d.applyOrganizationPolicy(nil); err != nil {
		t.Fatal(err)
	}
	if err := d.governance.Authorize(context.Background(), policy.CredentialUse, policy.Resource{Host: "denied.example"}); err != nil {
		t.Fatal("cleared policy did not restore unmanaged authorization")
	}
	if !backend.policy.DomainAllowed("other.example") {
		t.Fatal("cleared policy did not restore the local network policy")
	}
}

func TestLiveOrganizationPolicyUpdatesCredentialNetworkGateWithoutGuestNetwork(t *testing.T) {
	dir := t.TempDir()
	cfg := config.RunConfig{MemMB: 512, VCPUs: 1}
	if err := config.WriteSandboxConfig(dir, cfg); err != nil {
		t.Fatal(err)
	}
	store, err := config.LoadConfigStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	transactions := control.NewNetworkTransactionCoordinator()
	networkManager := control.NewNetworkPolicyManagerWithCoordinator(store, nil, netpol.DefaultPolicy(), transactions)
	d := &daemonSupervisor{
		dir: dir, cfg: cfg,
		governance: policy.NewController(nil), policyChanged: make(chan struct{}, 1),
	}
	d.host.SetConfig(store)
	d.host.SetAudit(&auditRing{})
	network := &Network{}
	d.host.SetNetwork(networkView{network: network}, network.CloseBackend, network.Close)
	d.host.SetTransactions(transactions)
	d.control.SetBroker(&broker{netPolicy: networkManager, domainAllowed: networkManager.DomainAllowed})
	d.control.SetShutdown(make(chan struct{}, 1))
	candidate := policytest.Signed(t, policy.Profile{
		Rules:   []policy.Rule{{ID: "credential", Effect: "allow", Action: policy.CredentialUse, Host: "allowed.example"}},
		Network: policy.Network{DNS: []string{"allowed.example"}},
	})
	if err := d.applyOrganizationPolicy(candidate); err != nil {
		t.Fatal(err)
	}
	if !d.credentialAllowed("allowed.example") || d.credentialAllowed("other.example") {
		t.Fatal("credential network gate did not follow live organization policy")
	}
	if err := d.applyOrganizationPolicy(nil); err != nil {
		t.Fatal(err)
	}
	if !d.credentialAllowed("other.example") {
		t.Fatal("credential network gate did not follow live policy clear")
	}
}

func TestLiveOrganizationPolicyNetworkFailureLeavesOldGeneration(t *testing.T) {
	d, backend := newLivePolicyDaemon(t)
	candidate := policytest.Signed(t, policy.Profile{})
	backend.fail = true
	if err := d.applyOrganizationPolicy(candidate); err == nil {
		t.Fatal("network update unexpectedly succeeded")
	}
	if d.governance.Snapshot() != nil {
		t.Fatal("failed policy generation was published")
	}
	saved, err := config.ReadSandboxConfig(d.dir)
	if err != nil {
		t.Fatal(err)
	}
	if saved.OrgPolicy != nil {
		t.Fatal("failed policy generation was persisted")
	}
	select {
	case <-d.control.Shutdown():
		t.Fatal("confirmed pre-commit failure should not stop the sandbox")
	default:
	}
}

func TestLiveOrganizationPolicyPersistenceFailureRollsBackNetwork(t *testing.T) {
	d, backend := newLivePolicyDaemon(t)
	configPath := filepath.Join(d.dir, "sandbox.json")
	if err := os.Remove(configPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(configPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := d.applyOrganizationPolicy(policytest.Signed(t, policy.Profile{})); err == nil {
		t.Fatal("policy update unexpectedly survived persistence failure")
	}
	if d.governance.Snapshot() != nil {
		t.Fatal("failed policy generation was published")
	}
	if !backend.policy.DomainAllowed("example.com") {
		t.Fatal("local network policy was not restored")
	}
	select {
	case <-d.control.Shutdown():
		t.Fatal("confirmed rollback should not stop the sandbox")
	default:
	}
}

func TestLiveOrganizationPolicyUnconfirmedRollbackStopsSandbox(t *testing.T) {
	d, backend := newLivePolicyDaemon(t)
	configPath := filepath.Join(d.dir, "sandbox.json")
	if err := os.Remove(configPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(configPath, 0o700); err != nil {
		t.Fatal(err)
	}
	backend.failCall = 3
	if err := d.applyOrganizationPolicy(policytest.Signed(t, policy.Profile{})); err == nil {
		t.Fatal("policy update unexpectedly succeeded")
	}
	select {
	case <-d.control.Shutdown():
	default:
		t.Fatal("unconfirmed rollback did not stop the sandbox")
	}
	decision := d.governance.Evaluate(context.Background(), policy.CredentialUse, policy.Resource{Host: "example.com"})
	if decision.Reason != "policy_update" {
		t.Fatalf("fail-closed barrier was released: %+v", decision)
	}
}

func TestLiveOrganizationPolicyDoesNotRereadLocalPolicySource(t *testing.T) {
	d, _ := newLivePolicyDaemon(t)
	missing := filepath.Join(t.TempDir(), "removed-policy.json")
	if err := d.host.Config().Mutate(func(cfg *config.RunConfig) error {
		cfg.NetPol = missing
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(missing)
	if err := d.applyOrganizationPolicy(policytest.Signed(t, policy.Profile{})); err != nil {
		t.Fatalf("live update reread removed local policy source: %v", err)
	}
}
