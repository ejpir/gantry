package config

import (
	"flag"
	"testing"

	"github.com/ejpir/gantry/internal/policy"
)

func TestOrganizationOptionsAndSnapshotAreDetached(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	flags := RegisterRunFlags(fs)
	if err := fs.Parse([]string{"-org-policy", "bundle.tar.gz", "-org-policy-key", "key.pem", "-policy-profile", "dev"}); err != nil {
		t.Fatal(err)
	}
	options := flags.Options(fs)
	if options.OrgPolicy != "bundle.tar.gz" || options.OrgPolicyKey != "key.pem" || options.PolicyProfile != "dev" {
		t.Fatalf("missing organization options: %+v", options)
	}
	original := RunConfig{OrgPolicy: &policy.Config{Bundle: []byte{1, 2, 3}, PublicKey: "key", Profile: "dev"}}
	clone := cloneRunConfig(original)
	clone.OrgPolicy.Bundle[0] = 99
	clone.OrgPolicy.PublicKey = "other"
	if original.OrgPolicy.Bundle[0] != 1 || original.OrgPolicy.PublicKey != "key" {
		t.Fatal("config snapshot aliases pinned policy")
	}
}
