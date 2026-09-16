package policy

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"slices"
	"time"

	"github.com/open-policy-agent/opa/v1/bundle"
)

// SignedDocument contains publishable artifacts only, never a private key.
type SignedDocument struct {
	Data      []byte
	Bundle    []byte
	PublicKey []byte
}

// ReadDocument reads bounded, data-only JSON using the same schema and expiry
// validation as activation. It does not authorize the data or establish trust.
func ReadDocument(path string) (Document, error) {
	raw, err := readLimitedFile(path, maxExpandedBytes)
	if err != nil {
		return Document{}, fmt.Errorf("policy data: %w", err)
	}
	return parseDocument(raw)
}

func parseDocument(raw []byte) (Document, error) {
	var root struct {
		Gantry Document `json:"gantry"`
	}
	if len(raw) > maxExpandedBytes {
		return root.Gantry, fmt.Errorf("policy data exceeds %d bytes", maxExpandedBytes)
	}
	if err := decodeStrict(raw, &root); err != nil {
		return root.Gantry, fmt.Errorf("policy schema: %w", err)
	}
	return root.Gantry, validateDocument(root.Gantry)
}

func validateDocument(document Document) error {
	if document.Version != 1 || !validID(document.Organization) || !validID(document.Revision) || document.ExpiresAt.IsZero() {
		return fmt.Errorf("policy requires version 1, organization, revision and expires_at")
	}
	if !time.Now().Before(document.ExpiresAt) {
		return fmt.Errorf("organization policy expired")
	}
	if len(document.Profiles) == 0 || len(document.Profiles) > 32 {
		return fmt.Errorf("policy requires 1..32 profiles")
	}
	for name, profile := range document.Profiles {
		if !validID(name) {
			return fmt.Errorf("invalid policy profile name")
		}
		if err := validateProfile(document, profile); err != nil {
			return fmt.Errorf("profile %s: %w", name, err)
		}
	}
	return nil
}

// MarshalDocument validates a draft and renders editable root data.json.
func MarshalDocument(document Document) ([]byte, error) {
	if err := validateDocument(document); err != nil {
		return nil, err
	}
	raw, err := json.MarshalIndent(struct {
		Gantry Document `json:"gantry"`
	}{document}, "", "  ")
	if err != nil {
		return nil, err
	}
	if len(raw)+1 > maxExpandedBytes {
		return nil, fmt.Errorf("policy data exceeds %d bytes", maxExpandedBytes)
	}
	return append(raw, '\n'), nil
}

// ReadSigningKey accepts one unencrypted PKCS#1 or PKCS#8 RSA private key.
// Parse diagnostics deliberately omit key material and ASN.1 details.
func ReadSigningKey(path string) (*rsa.PrivateKey, error) {
	raw, err := readLimitedFile(path, maxKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("signing key: %w", err)
	}
	block, rest := pem.Decode(raw)
	if block == nil || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("signing key must be one unencrypted PEM RSA private key")
	}
	var key *rsa.PrivateKey
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		var parsed any
		parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		key, _ = parsed.(*rsa.PrivateKey)
	default:
		return nil, fmt.Errorf("signing key must be one unencrypted PEM RSA private key")
	}
	if err != nil || !validSigningKey(key) {
		return nil, fmt.Errorf("signing key must be a valid RSA private key of at least 2048 bits")
	}
	return key, nil
}

func validSigningKey(key *rsa.PrivateKey) bool {
	if key == nil || key.N == nil || key.D == nil || key.N.BitLen() < 2048 {
		return false
	}
	for _, prime := range key.Primes {
		if prime == nil {
			return false
		}
	}
	return key.Validate() == nil
}

// SignDocument creates an RS256 data-only OPA bundle and verifies the result
// through the normal activation path before returning publishable artifacts.
// Signing never changes mounts, TTLs, revisions, profiles, or rule permissions.
func SignDocument(document Document, key *rsa.PrivateKey) (SignedDocument, error) {
	var signed SignedDocument
	raw, err := MarshalDocument(document)
	if err != nil {
		return signed, err
	}
	if !validSigningKey(key) {
		return signed, fmt.Errorf("signing key must be a valid RSA private key of at least 2048 bits")
	}
	var data map[string]any
	if err := json.Unmarshal(raw, &data); err != nil {
		return signed, err
	}
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return signed, err
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: public})
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	b := bundle.Bundle{Data: data, Manifest: bundle.Manifest{Roots: &[]string{""}}}
	if err := b.GenerateSignature(bundle.NewSigningConfig(string(privatePEM), "RS256", ""), "gantry", false); err != nil {
		// OPA's signer owns private material. Do not expose its diagnostics.
		return signed, fmt.Errorf("sign organization bundle failed")
	}
	var output bytes.Buffer
	if err := bundle.NewWriter(&output).Write(b); err != nil {
		return signed, fmt.Errorf("write organization bundle: %w", err)
	}
	profiles := make([]string, 0, len(document.Profiles))
	for profile := range document.Profiles {
		profiles = append(profiles, profile)
	}
	slices.Sort(profiles)
	if _, _, err := verify(&Config{Bundle: output.Bytes(), PublicKey: string(publicPEM), Profile: profiles[0]}); err != nil {
		return signed, fmt.Errorf("verify generated bundle: %w", err)
	}
	return SignedDocument{Data: raw, Bundle: output.Bytes(), PublicKey: publicPEM}, nil
}
