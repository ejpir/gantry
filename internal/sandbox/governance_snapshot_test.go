package sandbox

import (
	"bytes"
	"testing"

	"github.com/ejpir/gantry/internal/policy"
	"github.com/ejpir/gantry/internal/policy/policytest"
	"github.com/ejpir/gantry/internal/sandbox/config"
)

func TestRemoteOrganizationSnapshotIsVerifiedAndClonedBeforeBoot(t *testing.T) {
	snapshot := policytest.Signed(t, policy.Profile{})
	r := runResolver{options: config.RunOptions{OrganizationSnapshot: snapshot}}
	if err := r.resolveOrganizationPolicy(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(r.cfg.OrgPolicy.Bundle, snapshot.Bundle) {
		t.Fatal("snapshot was not applied")
	}
	snapshot.Bundle[0] ^= 1
	if _, err := policy.New(r.cfg.OrgPolicy, nil); err != nil {
		t.Fatal("request mutation changed verified snapshot")
	}
	r = runResolver{options: config.RunOptions{OrganizationSnapshot: snapshot}}
	if err := r.resolveOrganizationPolicy(); err == nil || r.cfg.OrgPolicy != nil {
		t.Fatal("tampered remote bundle accepted")
	}
}

func TestRemoteOrganizationSnapshotRejectsAmbiguousSourcesAndCustody(t *testing.T) {
	snapshot := policytest.Signed(t, policy.Profile{})
	for _, options := range []config.RunOptions{
		{OrganizationSnapshot: snapshot, OrgPolicy: "/host/bundle"},
		{OrganizationSnapshot: snapshot, OrgPolicyKey: "/host/key"},
		{OrganizationSnapshot: snapshot, PolicyProfile: "dev"},
		{OrganizationSnapshot: snapshot, OAuthCustody: true},
	} {
		r := runResolver{options: options}
		if err := r.resolveOrganizationPolicy(); err == nil {
			t.Fatal("ambiguous/unsupported organization launch accepted")
		}
	}
}
