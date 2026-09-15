package controlcmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ejpir/gantry/internal/policy"
	"github.com/ejpir/gantry/internal/policy/policytest"
)

func TestPolicyCLIUsesSignedProfileAndStrictCheckInput(t *testing.T) {
	c := policytest.Signed(t, policy.Profile{Rules: []policy.Rule{{ID: "read", Effect: "allow", Action: policy.MCPCall, Server: "fs", Tool: "read_file"}}})
	dir := t.TempDir()
	bp, kp := filepath.Join(dir, "policy.tar.gz"), filepath.Join(dir, "public.pem")
	if err := os.WriteFile(bp, c.Bundle, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kp, []byte(c.PublicKey), 0600); err != nil {
		t.Fatal(err)
	}
	flags := []string{"-bundle", bp, "-key", kp, "-profile", "dev"}
	if got := CmdPolicy(append([]string{"verify"}, flags...)); got != 0 {
		t.Fatalf("verify=%d", got)
	}
	for _, tc := range []struct {
		resource string
		want     int
	}{
		{`{"server":"fs","tool":"read_file"}`, 0},
		{`{"server":"fs","tool":"write_file"}`, 1},
		{`{"server":"fs","tool":"read_file","principal":"admin"}`, 1},
		{`{"server":"fs","tool":"read_file"} {}`, 1},
	} {
		args := append([]string{"check"}, flags...)
		args = append(args, "-action", policy.MCPCall, "-resource", tc.resource)
		if got := CmdPolicy(args); got != tc.want {
			t.Errorf("%s: exit %d", tc.resource, got)
		}
	}

	called := false
	rollout := func(name string, snapshot *policy.Config) error {
		called = true
		if name != "dev" || snapshot == nil || snapshot.Profile != "dev" {
			t.Fatalf("rollout = %q, %#v", name, snapshot)
		}
		return nil
	}
	args := append([]string{"set", "dev"}, flags...)
	args = append(args, "--restart")
	if got := CmdPolicyWithRollout(args, rollout); got != 0 || !called {
		t.Fatalf("restart set = %d, called=%t", got, called)
	}
	called = false
	if got := CmdPolicyWithRollout([]string{"clear", "dev", "--restart"}, func(name string, snapshot *policy.Config) error {
		called = name == "dev" && snapshot == nil
		return nil
	}); got != 0 || !called {
		t.Fatalf("restart clear = %d, called=%t", got, called)
	}
}

func TestSetOrganizationPolicyUsesRunningDaemon(t *testing.T) {
	useShortGantryHome(t)
	candidate := policytest.Signed(t, policy.Profile{})
	captured := fakeLiveSandbox(t, "policy-live", `{"ok":true}`)
	if err := SetOrganizationPolicy("policy-live", candidate); err != nil {
		t.Fatal(err)
	}
	request := <-captured
	if request.Op != "policy.set" || request.Policy == nil || request.Policy.Clear || request.Policy.Snapshot == nil {
		t.Fatalf("live policy request = %+v", request)
	}
	if request.Policy.Snapshot.Profile != candidate.Profile {
		t.Fatalf("live policy profile = %q", request.Policy.Snapshot.Profile)
	}
}
