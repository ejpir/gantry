package policy_test

import (
	"context"
	"testing"

	"github.com/ejpir/gantry/internal/policy"
	"github.com/ejpir/gantry/internal/policy/policytest"
)

func TestControllerBlocksAndPublishesPolicyAtomically(t *testing.T) {
	oldEngine, err := policy.New(policytest.Signed(t, policy.Profile{Rules: []policy.Rule{{
		ID: "old", Effect: "allow", Action: policy.CredentialUse, Host: "old.example",
	}}}), nil)
	if err != nil {
		t.Fatal(err)
	}
	newEngine, err := policy.New(policytest.Signed(t, policy.Profile{Rules: []policy.Rule{{
		ID: "new", Effect: "allow", Action: policy.CredentialUse, Host: "new.example",
	}}}), nil)
	if err != nil {
		t.Fatal(err)
	}
	controller := policy.NewController(oldEngine)
	authorize := func(host string) error {
		return controller.Authorize(context.Background(), policy.CredentialUse, policy.Resource{Host: host})
	}
	if err := authorize("old.example"); err != nil {
		t.Fatal(err)
	}
	controller.SetBlocked(true)
	if decision := controller.Evaluate(context.Background(), policy.CredentialUse, policy.Resource{Host: "old.example"}); decision.Effect != "deny" || decision.Reason != "policy_update" {
		t.Fatalf("barrier decision = %+v", decision)
	}
	controller.Store(newEngine)
	if err := authorize("new.example"); err == nil {
		t.Fatal("new policy became usable before the update barrier was released")
	}
	controller.SetBlocked(false)
	if err := authorize("new.example"); err != nil {
		t.Fatal(err)
	}
	if err := authorize("old.example"); err == nil {
		t.Fatal("old policy remained active after publication")
	}
}

func TestUnmanagedControllerAllowsRequests(t *testing.T) {
	controller := policy.NewController(nil)
	if err := controller.Authorize(context.Background(), policy.CredentialUse, policy.Resource{Host: "example.com"}); err != nil {
		t.Fatal(err)
	}
	if !controller.ExpiresAt().IsZero() || controller.Info() != (policy.SnapshotInfo{}) {
		t.Fatal("unmanaged controller reported policy metadata")
	}
}
