package policy_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ejpir/gantry/internal/policy"
)

var authorKey = sync.OnceValues(func() (*rsa.PrivateKey, error) { return rsa.GenerateKey(rand.Reader, 2048) })

func testAuthorKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := authorKey()
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func authorDocument() policy.Document {
	return policy.Document{Version: 1, Organization: "author-org", Revision: "r1", ExpiresAt: time.Now().Add(time.Hour).UTC(), Profiles: map[string]policy.Profile{
		"developer": {Rules: []policy.Rule{{ID: "read", Effect: "allow", Action: policy.MCPCall, Server: "fs", Tool: "read_file"}}},
		"locked":    {},
	}}
}

func TestSignDocumentRoundTripAndDataOnly(t *testing.T) {
	document := authorDocument()
	key := testAuthorKey(t)
	signed, err := policy.SignDocument(document, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "data.json")
	if err := os.WriteFile(path, signed.Data, 0o600); err != nil {
		t.Fatal(err)
	}
	decoded, err := policy.ReadDocument(path)
	if err != nil || !reflect.DeepEqual(decoded, document) {
		t.Fatalf("source changed semantics: %+v, %v", decoded, err)
	}
	for _, profile := range []string{"developer", "locked"} {
		engine, err := policy.New(&policy.Config{Bundle: signed.Bundle, PublicKey: string(signed.PublicKey), Profile: profile}, nil)
		if err != nil {
			t.Fatal(err)
		}
		info := engine.Info()
		if info.Organization != document.Organization || info.Revision != document.Revision || !info.ExpiresAt.Equal(document.ExpiresAt) || info.Profile != profile {
			t.Fatalf("provenance changed: %+v", info)
		}
		decision := engine.Evaluate(context.Background(), policy.MCPCall, policy.Resource{Server: "fs", Tool: "read_file"})
		if (decision.Effect == "allow") != (profile == "developer") {
			t.Fatalf("profile permissions changed: %+v", decision)
		}
	}
	gz, err := gzip.NewReader(bytes.NewReader(signed.Bundle))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(gz)
	seen := make(map[string]bool)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		name := strings.TrimPrefix(header.Name, "/")
		seen[name] = true
		content, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		switch name {
		case "data.json":
			var expected, actual any
			if err := json.Unmarshal(signed.Data, &expected); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(content, &actual); err != nil || !reflect.DeepEqual(actual, expected) {
				t.Fatal("signed data differs from editable source")
			}
		case ".signatures.json", ".manifest":
		default:
			t.Fatalf("unexpected archive entry: %s", name)
		}
		if bytes.Contains(content, []byte("PRIVATE KEY")) {
			t.Fatal("private key published in bundle")
		}
	}
	if !seen["data.json"] || !seen[".signatures.json"] || bytes.Contains(signed.PublicKey, []byte("PRIVATE KEY")) {
		t.Fatal("missing signature/data or private key publication")
	}
}

func TestAuthoringUsesActivationSchema(t *testing.T) {
	valid, err := policy.MarshalDocument(authorDocument())
	if err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string][]byte{
		"unknown field": bytes.Replace(valid, []byte(`"version": 1`), []byte(`"version": 1, "principal": "admin"`), 1),
		"trailing JSON": append(bytes.Clone(valid), []byte(`{}`)...),
		"empty":         {},
		"null":          []byte(`null`),
		"oversized":     bytes.Repeat([]byte(" "), (2<<20)+1),
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "data.json")
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := policy.ReadDocument(path); err == nil {
				t.Fatal("invalid source accepted")
			}
		})
	}
	for name, change := range map[string]func(*policy.Document){
		"expired":          func(d *policy.Document) { d.ExpiresAt = time.Now().Add(-time.Second) },
		"bad organization": func(d *policy.Document) { d.Organization = "bad/name" },
		"no profiles":      func(d *policy.Document) { d.Profiles = nil },
		"unknown action": func(d *policy.Document) {
			d.Profiles["locked"] = policy.Profile{Rules: []policy.Rule{{ID: "x", Effect: "allow", Action: "shell.exec"}}}
		},
		"duplicate rule": func(d *policy.Document) {
			p := d.Profiles["developer"]
			p.Rules = append(p.Rules, p.Rules[0])
			d.Profiles["developer"] = p
		},
	} {
		t.Run(name, func(t *testing.T) {
			doc := authorDocument()
			change(&doc)
			if _, err := policy.MarshalDocument(doc); err == nil {
				t.Fatal("invalid source marshaled")
			}
			if _, err := policy.SignDocument(doc, testAuthorKey(t)); err == nil {
				t.Fatal("invalid source signed")
			}
		})
	}
}

func TestReadSigningKeyFormatsAndRejection(t *testing.T) {
	key := testAuthorKey(t)
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pkcs1 := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	for name, raw := range map[string][]byte{
		"pkcs1": pkcs1,
		"pkcs8": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}),
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "private.pem")
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			parsed, err := policy.ReadSigningKey(path)
			if err != nil || parsed.N.Cmp(key.N) != 0 {
				t.Fatalf("valid key rejected: %v", err)
			}
		})
	}
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecDER, err := x509.MarshalPKCS8PrivateKey(ec)
	if err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string][]byte{
		"public":    pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&key.PublicKey)}),
		"weak":      pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(weak)}),
		"ec":        pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: ecDER}),
		"encrypted": pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte("PRIVATE-KEY-CANARY")}),
		"malformed": pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte("PRIVATE-KEY-CANARY")}),
		"multiple":  append(bytes.Clone(pkcs1), pkcs1...),
		"oversized": bytes.Repeat([]byte("PRIVATE-KEY-CANARY"), 1024),
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "private.pem")
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := policy.ReadSigningKey(path); err == nil || strings.Contains(err.Error(), "PRIVATE-KEY-CANARY") {
				t.Fatalf("invalid key accepted or echoed: %v", err)
			}
		})
	}
	for _, invalid := range []*rsa.PrivateKey{nil, {}, weak} {
		if _, err := policy.SignDocument(authorDocument(), invalid); err == nil {
			t.Fatal("invalid signing key accepted")
		}
	}
	if _, err := policy.ReadSigningKey(t.TempDir()); err == nil {
		t.Fatal("directory accepted as key")
	}
}
