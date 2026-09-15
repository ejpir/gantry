// Package remoteprofile defines credential-free manager connection metadata.
// Local profiles and organization catalogs share this shape and validation;
// bearer credentials are deliberately stored elsewhere.
package remoteprofile

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/ejpir/gantry/internal/sandbox/layout"
)

type Profile struct {
	Name        string `json:"name"`
	URL         string `json:"url"`
	Fingerprint string `json:"fingerprint,omitempty"`
	CACert      string `json:"caCert,omitempty"`
}

var fingerprintPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func Validate(profile Profile) error {
	if err := layout.ValidateName(profile.Name); err != nil {
		return fmt.Errorf("remote name: %w", err)
	}
	if strings.Contains(profile.Name, ".") {
		return fmt.Errorf("remote name must be a single hostname label (no dots)")
	}
	u, err := url.Parse(profile.URL)
	if err != nil {
		return fmt.Errorf("invalid remote URL")
	}
	if u.User != nil {
		return fmt.Errorf("remote URL must not contain credentials; the token is stored separately")
	}
	if u.Scheme != "https" {
		return fmt.Errorf("remote URL must use https:// (plaintext remote access is not supported)")
	}
	if u.Host == "" || u.Hostname() == "" {
		return fmt.Errorf("remote URL has no host")
	}
	if len(profile.URL) > 2048 || u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(profile.URL, "#") || u.Opaque != "" {
		return fmt.Errorf("remote URL must be just https://HOST[:PORT]")
	}
	if profile.Fingerprint != "" && !fingerprintPattern.MatchString(profile.Fingerprint) {
		return fmt.Errorf("fingerprint must be sha256:<64 lowercase hex chars>")
	}
	return ValidateCA(profile.CACert)
}

// ValidateCA accepts only public certificates. Do not silently persist an
// appended private key (AppendCertsFromPEM would otherwise ignore it).
func ValidateCA(bundle string) error {
	if len(bundle) > 64<<10 {
		return fmt.Errorf("remote CA bundle exceeds 64 KiB")
	}
	data := strings.TrimSpace(bundle)
	if bundle != "" && data == "" {
		return fmt.Errorf("remote CA bundle has no PEM certificates")
	}
	for data != "" {
		if !strings.HasPrefix(data, "-----BEGIN CERTIFICATE-----") {
			return fmt.Errorf("remote CA bundle must contain only public PEM certificates")
		}
		block, rest := pem.Decode([]byte(data))
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return fmt.Errorf("remote CA bundle has invalid PEM certificates")
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return fmt.Errorf("remote CA bundle has invalid certificates")
		}
		data = strings.TrimSpace(string(rest))
	}
	return nil
}
