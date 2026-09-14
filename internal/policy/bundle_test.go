package policy_test

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ejpir/gantry/internal/policy"
	"github.com/ejpir/gantry/internal/policy/policytest"
	"github.com/open-policy-agent/opa/v1/bundle"
)

func TestSignatureVerificationCannotBeSkipped(t *testing.T) {
	original := policytest.Signed(t, policy.Profile{})
	for _, unsigned := range []bool{false, true} {
		verification := bundle.NewVerificationConfig(map[string]*bundle.KeyConfig{
			"gantry": {Key: original.PublicKey, Algorithm: "RS256"},
		}, "gantry", "", nil)
		parsed, err := bundle.NewReader(bytes.NewReader(original.Bundle)).WithBundleVerificationConfig(verification).Read()
		if err != nil {
			t.Fatal(err)
		}
		if unsigned {
			parsed.Signatures = bundle.SignaturesConfig{}
		} else {
			// Keep the valid signature, but change the authenticated data. This
			// remains a well-formed gzip/tar/JSON bundle, not a framing failure.
			parsed.Data["gantry"].(map[string]any)["organization"] = "attacker"
		}
		var output bytes.Buffer
		if err := bundle.NewWriter(&output).Write(parsed); err != nil {
			t.Fatal(err)
		}
		config := policy.CloneConfig(original)
		config.Bundle = output.Bytes()
		if _, err := policy.New(config, nil); err == nil {
			t.Fatalf("accepted unverified data (unsigned=%v)", unsigned)
		} else if !unsigned && !strings.Contains(err.Error(), "digest mismatch") {
			t.Fatalf("tamper fixture must exercise signature verification, not missing-signature/framing rejection: %v", err)
		}
	}
}

func TestSnapshotExpiresWithoutReload(t *testing.T) {
	expires := time.Now().Add(2 * time.Second).UTC()
	config := policytest.Document(t, policy.Document{Version: 1, Organization: "org", Revision: "r1", ExpiresAt: expires, Profiles: map[string]policy.Profile{"dev": {Rules: []policy.Rule{{ID: "credential", Effect: "allow", Action: policy.CredentialUse, Host: "example.com"}}}}})
	engine, err := policy.New(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	resource := policy.Resource{Host: "example.com"}
	if time.Until(expires) > 0 && engine.Evaluate(context.Background(), policy.CredentialUse, resource).Effect != "allow" {
		t.Fatal("valid snapshot denied")
	}
	time.Sleep(max(0, time.Until(expires)) + time.Millisecond)
	decision := engine.Evaluate(context.Background(), policy.CredentialUse, resource)
	if decision.Effect != "deny" || decision.Reason != "policy_expired" {
		t.Fatalf("expired snapshot: %+v", decision)
	}
}
