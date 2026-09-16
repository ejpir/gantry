// Package policytest creates real signed OPA snapshots for enforcement tests.
package policytest

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"sync"
	"testing"
	"time"

	"github.com/ejpir/gantry/internal/policy"
	"github.com/open-policy-agent/opa/v1/bundle"
)

var signingKey = sync.OnceValues(func() (*rsa.PrivateKey, error) { return rsa.GenerateKey(rand.Reader, 2048) })

func Signed(t testing.TB, profile policy.Profile) *policy.Config {
	t.Helper()
	return Document(t, policy.Document{Version: 1, Organization: "test-org", Revision: "r1", ExpiresAt: time.Now().Add(time.Hour).UTC(), Profiles: map[string]policy.Profile{"dev": profile}})
}

func Document(t testing.TB, document policy.Document) *policy.Config {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"gantry": document})
	if err != nil {
		t.Fatal(err)
	}
	var data map[string]any
	if err := json.Unmarshal(raw, &data); err != nil {
		t.Fatal(err)
	}
	return Data(t, data)
}

func Data(t testing.TB, data map[string]any) *policy.Config {
	t.Helper()
	key, err := signingKey()
	if err != nil {
		t.Fatal(err)
	}
	private := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	public := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&key.PublicKey)})
	b := bundle.Bundle{Data: data, Manifest: bundle.Manifest{Roots: &[]string{""}}}
	if err := b.GenerateSignature(bundle.NewSigningConfig(string(private), "RS256", ""), "gantry", false); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := bundle.NewWriter(&out).Write(b); err != nil {
		t.Fatal(err)
	}
	return &policy.Config{Bundle: out.Bytes(), PublicKey: string(public), Profile: "dev"}
}
