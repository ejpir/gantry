package remote

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/ejpir/gantry/api/managerapi"
	"github.com/ejpir/gantry/internal/policy"
	"github.com/ejpir/gantry/internal/policy/policytest"
)

func TestRemotePolicyRestartRequest(t *testing.T) {
	snapshot := policytest.Signed(t, policy.Profile{})
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.tar.gz")
	keyPath := filepath.Join(dir, "public.pem")
	if err := os.WriteFile(bundlePath, snapshot.Bundle, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte(snapshot.PublicKey), 0o600); err != nil {
		t.Fatal(err)
	}
	var request managerapi.OrganizationPolicyRequest
	client, output, errorOutput := verbHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/sandboxes/dev/policy" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
		}
		_ = json.NewEncoder(w).Encode(managerapi.Operation{ID: "policy-1", Kind: "policy", State: "succeeded", Progress: "organization policy active after controlled restart"})
	}))
	status := remotePolicy(t.Context(), output, errorOutput, "stub", client, "policy", []string{
		"set", "dev", "-bundle", bundlePath, "-key", keyPath, "-profile", "dev", "--restart",
	})
	if status != 0 {
		t.Fatalf("policy set = %d (%s)", status, errorOutput)
	}
	if !request.Restart || request.Clear || request.Snapshot == nil {
		t.Fatalf("request = %#v", request)
	}
}
