package control

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ejpir/gantry/internal/policy"
	"github.com/ejpir/gantry/internal/policy/policytest"
	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/shares"
)

func TestShareManagerReconcilesLiveOrganizationPolicy(t *testing.T) {
	dir := t.TempDir()
	shared := t.TempDir()
	cfg := config.RunConfig{MemMB: 512, VCPUs: 1, RW: true, Shares: []string{"code=" + shared + ",ro"}}
	if err := config.WriteSandboxConfig(dir, cfg); err != nil {
		t.Fatal(err)
	}
	store, err := config.LoadConfigStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	controller := policy.NewController(nil)
	manager, _, err := NewShareManagerWithController(dir, store, controller)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = manager.Close() }()

	denied, err := policy.New(policytest.Signed(t, policy.Profile{}), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.ReconcileOrganizationPolicy(denied); err != nil {
		t.Fatal(err)
	}
	entries := manager.Entries()
	if len(entries) != 1 || entries[0].State != "policy-denied" {
		t.Fatalf("denied entries = %+v", entries)
	}
	var manifest shares.Manifest
	raw, err := os.ReadFile(filepath.Join(dir, "shares.json"))
	if err != nil || json.Unmarshal(raw, &manifest) != nil || len(manifest.Shares) != 1 || manifest.Shares[0].State != "policy-denied" {
		t.Fatalf("policy-denied manifest = %+v, err=%v", manifest, err)
	}
	if err := manager.ReconcileOrganizationPolicy(nil); err != nil {
		t.Fatal(err)
	}
	entries = manager.Entries()
	if len(entries) != 1 || entries[0].State != "active" {
		t.Fatalf("restored entries = %+v", entries)
	}
}
