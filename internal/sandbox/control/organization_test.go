//go:build linux || darwin

package control

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ejpir/gantry/internal/netpol"
	"github.com/ejpir/gantry/internal/policy"
	"github.com/ejpir/gantry/internal/policy/policytest"
	"github.com/ejpir/gantry/internal/sandbox/config"
)

func TestOrganizationMountsUsePinnedRootAndCheckReplacement(t *testing.T) {
	root := canonicalControlTestPath(t, t.TempDir())
	other := canonicalControlTestPath(t, t.TempDir())
	org := policytest.Signed(t, policy.Profile{Rules: []policy.Rule{{ID: "read", Effect: "allow", Action: policy.MountRead, Path: root}}})
	for _, spec := range []string{"code=" + root, "code=" + other + ",ro"} {
		store := newTestConfigStore(t, t.TempDir(), config.RunConfig{RW: true, Shares: []string{spec}, OrgPolicy: org})
		if m, _, err := NewShareManager(t.TempDir(), store); err == nil {
			_ = m.Close()
			t.Fatalf("initial denied mount accepted: %s", spec)
		}
	}
	dir := t.TempDir()
	store := newTestConfigStore(t, dir, config.RunConfig{RW: true, Shares: []string{"code=" + root + ",ro"}, OrgPolicy: org})
	m, _, err := NewShareManager(dir, store)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Close() }()
	if _, err := m.Add("code="+root, true, true); err == nil {
		t.Fatal("read-only to writable escalation accepted")
	}
	if _, err := m.Add("code="+other+",ro", true, true); err == nil {
		t.Fatal("unapproved replacement accepted")
	}
	if got := store.Snapshot().Shares; len(got) != 1 || !strings.HasSuffix(got[0], ",ro") {
		t.Fatalf("denial changed config: %v", got)
	}
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(other, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Add("alias="+alias+",ro", false, false); err == nil {
		t.Fatal("symlink to unapproved pinned root accepted")
	}
}

func TestOrganizationGuardSurvivesLocalPolicyManagerReset(t *testing.T) {
	org := policytest.Signed(t, policy.Profile{Network: policy.Network{Rules: []netpol.GuardRule{
		{ID: "only-https", Effect: "allow", CIDR: "1.1.1.1/32", Protocol: "tcp", Ports: []uint16{443}},
	}, DNS: []string{"example.com"}}})
	engine, err := policy.New(org, nil)
	if err != nil {
		t.Fatal(err)
	}
	live, err := engine.ApplyNetwork(netpol.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	store := newTestConfigStore(t, t.TempDir(), config.RunConfig{Net: true, OrgPolicy: org})
	manager := NewNetworkPolicyManager(store, &localBackend{stack: &localNetworkStackStub{}, live: live}, live)
	entry, err := manager.Set("", true)
	if err != nil {
		t.Fatal(err)
	}
	if live.Allows([4]byte{8, 8, 8, 8}, 6, 443) || live.Allows([4]byte{1, 1, 1, 1}, 6, 80) {
		t.Fatal("local reset widened organization permissions")
	}
	if !live.Allows([4]byte{1, 1, 1, 1}, 6, 443) {
		t.Fatal("allowed endpoint lost")
	}
	if !strings.Contains(entry.Description, "test-org") {
		t.Fatal("manager lost organization snapshot metadata")
	}
	shown, err := manager.Get()
	if err != nil || shown.Description != entry.Description {
		t.Fatalf("active view drifted: %+v %v", shown, err)
	}
}
