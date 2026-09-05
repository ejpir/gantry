package control

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ejpir/gantry/internal/atomicfile"
	"github.com/ejpir/gantry/internal/netpol"
	"github.com/ejpir/gantry/internal/sandbox/config"
)

func TestNetworkPolicyManagerAppliesAndPersists(t *testing.T) {
	dir := t.TempDir()
	store := newTestConfigStore(t, dir, config.RunConfig{Net: true})
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
	manager := NewNetworkPolicyManager(store, &localBackend{stack: &localNetworkStackStub{}, live: live}, live)
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

func TestSplitPolicyUpdateRefreshesHostCredentialGate(t *testing.T) {
	dir := t.TempDir()
	store := newTestConfigStore(t, dir, config.RunConfig{Net: true})
	policyPath := filepath.Join(dir, "gitlab.json")
	if err := os.WriteFile(policyPath, []byte(`{
		"default":"deny",
		"allowDomains":["gitlab.com"]
	}`), 0o600); err != nil {
		t.Fatal(err)
	}
	live := mustTestPolicy(t, `{"default":"deny","allowDomains":["github.com"]}`)
	split := &policyBackendStub{policy: mustPolicySnapshot(live)}
	backend, err := NewPolicyMirrorBackend(split, live)
	if err != nil {
		t.Fatal(err)
	}
	manager := NewNetworkPolicyManager(store, backend, live)
	credentialEgressAllowed := live.DomainAllowed
	if !credentialEgressAllowed("github.com") {
		t.Fatal("boot policy did not allow the bound credential host")
	}

	if _, err := manager.Set(policyPath, false); err != nil {
		t.Fatal(err)
	}
	if split.policy.DomainAllowed("github.com") {
		t.Fatal("split enforcement backend retained the boot policy")
	}
	if credentialEgressAllowed("github.com") {
		t.Fatal("host credential gate retained the boot policy")
	}
	if !credentialEgressAllowed("gitlab.com") {
		t.Fatal("host credential gate did not follow the active split policy")
	}
}

func TestNetworkPolicyManagerPreservesProxyEnforcement(t *testing.T) {
	dir := t.TempDir()
	store := newTestConfigStore(t, dir, config.RunConfig{
		Net: true, ProxyURL: "http://203.0.113.5:3128", ProxyEnforce: true,
	})
	live := netpol.DefaultPolicy()
	manager := NewNetworkPolicyManager(store, &localBackend{stack: &localNetworkStackStub{}, live: live}, live)

	entry, err := manager.Set("", false)
	if err != nil {
		t.Fatal(err)
	}
	if live.Allows([4]byte{8, 8, 8, 8}, 6, 443) {
		t.Fatal("live policy replacement bypassed proxy-only HTTPS enforcement")
	}
	if !live.Allows([4]byte{203, 0, 113, 5}, 6, 3128) {
		t.Fatal("live policy replacement blocked the configured proxy")
	}
	if !strings.Contains(entry.Description, "3 rules") {
		t.Fatalf("effective policy description = %q, want proxy overlay rules", entry.Description)
	}
	if cfg := store.Snapshot(); cfg.NetPol != "" || !cfg.ProxyEnforce {
		t.Fatalf("persisted config lost base/proxy separation: %+v", cfg)
	}
}

func TestNetworkPolicyManagerPersistenceFailureRestoresSnapshot(t *testing.T) {
	dir := t.TempDir()
	store := newTestConfigStore(t, dir, config.RunConfig{Net: true})
	policyPath := filepath.Join(dir, "deny.json")
	if err := os.WriteFile(policyPath, []byte(`{"default":"deny"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	// live is the stable holder mutated by localBackend.Replace. The manager
	// must retain an immutable old-policy snapshot rather than aliasing it.
	live := netpol.DefaultPolicy()
	manager := NewNetworkPolicyManager(store, &localBackend{stack: &localNetworkStackStub{}, live: live}, live)
	store.SetWriter(func(string, []byte, os.FileMode) error {
		return errors.New("config path is unwritable")
	})
	if _, err := manager.Set(policyPath, false); err == nil {
		t.Fatal("unwritable config path reported success")
	}
	if !live.Allows([4]byte{8, 8, 8, 8}, 6, 443) {
		t.Fatal("persistence failure left the attempted deny policy active")
	}
	if cfg := store.Snapshot(); cfg.NetPol != "" || cfg.AllowLN {
		t.Fatalf("persistence failure changed config: %+v", cfg)
	}
}

func TestNetworkPolicyManagerKeepsCommittedPolicyOnDurabilityError(t *testing.T) {
	dir := t.TempDir()
	store := newTestConfigStore(t, dir, config.RunConfig{Net: true})
	policyPath := filepath.Join(dir, "deny.json")
	if err := os.WriteFile(policyPath, []byte(`{"default":"deny"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	wantErr := errors.New("directory sync failed")
	store.SetWriter(func(path string, data []byte, mode os.FileMode) error {
		if err := os.WriteFile(path, data, mode); err != nil {
			return err
		}
		return &atomicfile.CommitError{Err: wantErr}
	})

	live := netpol.DefaultPolicy()
	manager := NewNetworkPolicyManager(store, &localBackend{stack: &localNetworkStackStub{}, live: live}, live)
	entry, err := manager.Set(policyPath, false)
	if !atomicfile.Committed(err) || !errors.Is(err, wantErr) {
		t.Fatalf("Set error = %v, want committed durability error", err)
	}
	if entry.State != "active" || live.Allows([4]byte{8, 8, 8, 8}, 6, 443) {
		t.Fatalf("committed live policy = %+v", entry)
	}
	if cfg := store.Snapshot(); cfg.NetPol == "" {
		t.Fatalf("committed configuration was rolled back: %+v", cfg)
	}
}

func TestNetworkPolicyManagerReportsFailedPersistenceRollback(t *testing.T) {
	dir := t.TempDir()
	store := newTestConfigStore(t, dir, config.RunConfig{Net: true})
	policyPath := filepath.Join(dir, "deny.json")
	if err := os.WriteFile(policyPath, []byte(`{"default":"deny"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	old := netpol.DefaultPolicy()
	backend := &policyBackendStub{
		policy: mustPolicySnapshot(old), failAt: 2, failAtErr: fmt.Errorf("injected rollback failure"),
	}
	manager := NewNetworkPolicyManager(store, backend, old)
	store.SetWriter(func(string, []byte, os.FileMode) error {
		return errors.New("config path is unwritable")
	})
	_, err := manager.Set(policyPath, false)
	if err == nil || !strings.Contains(err.Error(), "restore previous live network policy") {
		t.Fatalf("persistence rollback error = %v", err)
	}
}
