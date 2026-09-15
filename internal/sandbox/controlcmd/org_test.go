package controlcmd

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/ejpir/gantry/internal/orgauth"
	"github.com/ejpir/gantry/internal/policy"
	"github.com/ejpir/gantry/internal/policy/policytest"
	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/layout"
)

func orgSessionFixture(t *testing.T) *orgauth.Session {
	t.Helper()
	return &orgauth.Session{
		Version: 1, Organization: "test-org", Issuer: "https://issuer.example", ClientID: "client", Subject: "user", Profile: "dev",
		ExpiresAt: time.Now().Add(time.Minute), Policy: policytest.Signed(t, policy.Profile{}),
	}
}

func TestOrgApplyPinsStoppedSnapshotAndUsesLiveDaemon(t *testing.T) {
	useShortGantryHome(t)
	session := orgSessionFixture(t)
	dir := writeSandboxConfig(t, "stopped")
	if err := orgauth.SaveSession(orgSessionDir(), session); err != nil {
		t.Fatal(err)
	}
	// The session store is a sibling of the sandbox root and remains under the
	// exact same host-state overlap barrier used by all ordinary guest shares.
	if filepath.Dir(orgSessionDir()) != layout.ProtectionRoot(dir) {
		t.Fatal("organization receipts are outside protected state")
	}
	if code := CmdOrg([]string{"apply", "test-org", "stopped"}); code != 0 {
		t.Fatalf("apply exit = %d", code)
	}
	cfg, err := config.ReadSandboxConfig(dir)
	if err != nil || cfg.OrgPolicy == nil || cfg.OrgPolicy.Profile != "dev" {
		t.Fatalf("snapshot not pinned: %v", err)
	}
	session.Policy.Bundle[0] ^= 1
	if _, err := policy.New(cfg.OrgPolicy, nil); err != nil {
		t.Fatal("stored snapshot aliases caller input")
	}
	if code := CmdOrg([]string{"status", "test-org"}); code != 0 {
		t.Fatalf("status exit = %d", code)
	}
	if code := CmdOrg([]string{"logout", "test-org"}); code != 0 {
		t.Fatalf("logout exit = %d", code)
	}
	if code := CmdOrg([]string{"apply", "test-org", "stopped"}); code == 0 {
		t.Fatal("logged-out session applied")
	}
	cfg, err = config.ReadSandboxConfig(dir)
	if err != nil || cfg.OrgPolicy == nil {
		t.Fatal("logout silently cleared pinned policy")
	}
	captured := fakeLiveSandbox(t, "live", `{"ok":true}`)
	if err := applyOrgSession("live", orgSessionFixture(t)); err != nil {
		t.Fatal(err)
	}
	request := <-captured
	if request.Op != "policy.set" || request.Policy == nil || request.Policy.Snapshot == nil {
		t.Fatalf("live organization apply request = %+v", request)
	}
}

func TestOrgApplyRejectsExpiredSessionsAndOAuthCustody(t *testing.T) {
	useShortGantryHome(t)
	dir := writeSandboxConfig(t, "test")
	session := orgSessionFixture(t)
	session.ExpiresAt = time.Now().Add(-time.Second)
	if err := applyOrgSession("test", session); err == nil {
		t.Fatal("expired login applied")
	}
	store, err := config.LoadConfigStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Mutate(func(c *config.RunConfig) error {
		enabled := true
		c.OAuthCustody = &enabled
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := applyOrgSession("test", orgSessionFixture(t)); err == nil {
		t.Fatal("organization login enabled unsupported guest OAuth custody")
	}
}

func TestOrgCLIUsage(t *testing.T) {
	useShortGantryHome(t)
	for _, args := range [][]string{{"bad"}, {"login"}, {"login", "-config", "missing", "-timeout", "0"}, {"login", "extra"}, {"status"}, {"logout", "../bad"}} {
		if CmdOrg(args) == 0 {
			t.Fatalf("invalid arguments accepted: %v", args)
		}
	}
	for _, args := range [][]string{nil, {"--help"}, {"login", "--help"}} {
		if CmdOrg(args) != 0 {
			t.Fatalf("help failed: %v", args)
		}
	}
}
