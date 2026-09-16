// Package policyfeed receives signed organization-policy generations from an
// explicitly configured HTTPS service. The channel is host-side: guests never
// receive its client identity, policy bundle, or transport connection.
package policyfeed

import (
	"bytes"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	maxConfigBytes = 64 << 10
	maxPEMBytes    = 64 << 10
	defaultPoll    = 30 * time.Second
	minimumPoll    = 5 * time.Second
	maximumPoll    = time.Hour
)

// Config pins one organization-wide policy feed and profile to this manager.
// Every sandbox managed by the server receives an accepted generation. Private
// key bytes are loaded into memory and never exposed through the JSON fields.
type Config struct {
	Version             int    `json:"version"`
	Organization        string `json:"organization"`
	Profile             string `json:"profile"`
	URL                 string `json:"url"`
	PublicKeyFile       string `json:"public_key"`
	CAFile              string `json:"ca_file,omitempty"`
	ClientCertificate   string `json:"client_certificate"`
	ClientKey           string `json:"client_key"`
	PollIntervalSeconds int    `json:"poll_interval_seconds,omitempty"`

	publicKey   string
	ca          []byte
	certificate tls.Certificate
	poll        time.Duration
}

// LoadConfig reads and pins all channel trust material. Paths are relative to
// the configuration file and symlinks are refused.
func LoadConfig(path string) (*Config, error) {
	raw, err := readRegular(path, maxConfigBytes)
	if err != nil {
		return nil, fmt.Errorf("policy channel configuration: %w", err)
	}
	var config Config
	if err := strictJSON(raw, &config); err != nil {
		return nil, fmt.Errorf("invalid policy channel configuration")
	}
	if config.Version != 1 || !identifier(config.Organization) || !identifier(config.Profile) {
		return nil, fmt.Errorf("policy channel requires version 1, organization and profile")
	}
	endpoint, err := url.Parse(config.URL)
	if err != nil || len(config.URL) > 2048 || endpoint.Scheme != "https" || endpoint.Hostname() == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.ForceQuery || endpoint.Fragment != "" || endpoint.Opaque != "" {
		return nil, fmt.Errorf("policy channel URL must be HTTPS without credentials, query or fragment")
	}
	if config.PublicKeyFile == "" || config.ClientCertificate == "" || config.ClientKey == "" {
		return nil, fmt.Errorf("policy channel requires public_key, client_certificate and client_key")
	}
	if config.PollIntervalSeconds == 0 {
		config.poll = defaultPoll
	} else {
		config.poll = time.Duration(config.PollIntervalSeconds) * time.Second
		if config.poll < minimumPoll || config.poll > maximumPoll {
			return nil, fmt.Errorf("policy channel poll interval must be 5..3600 seconds")
		}
	}
	resolve := func(name string) string {
		if name == "" || filepath.IsAbs(name) {
			return name
		}
		return filepath.Join(filepath.Dir(path), name)
	}
	publicKey, err := readRegular(resolve(config.PublicKeyFile), 16<<10)
	if err != nil || validatePublicKey(publicKey) != nil {
		return nil, fmt.Errorf("policy channel public key is invalid or unavailable")
	}
	var ca []byte
	if config.CAFile != "" {
		ca, err = readRegular(resolve(config.CAFile), maxPEMBytes)
		if err != nil {
			return nil, fmt.Errorf("policy channel CA file is unavailable")
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(ca) {
			return nil, fmt.Errorf("policy channel CA file contains no certificates")
		}
	}
	certPEM, err := readRegular(resolve(config.ClientCertificate), maxPEMBytes)
	if err != nil {
		return nil, fmt.Errorf("policy channel client certificate is unavailable")
	}
	keyPath := resolve(config.ClientKey)
	keyInfo, err := os.Lstat(keyPath)
	if err != nil || keyInfo.Mode()&os.ModeSymlink != 0 || !keyInfo.Mode().IsRegular() {
		return nil, fmt.Errorf("policy channel client key must be a regular file (no symlinks)")
	}
	if err := validatePrivateFile(keyPath, keyInfo); err != nil {
		return nil, fmt.Errorf("policy channel client key is not private: %w", err)
	}
	keyPEM, err := readRegular(keyPath, maxPEMBytes)
	if err != nil {
		return nil, fmt.Errorf("policy channel client key is unavailable")
	}
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil || len(certificate.Certificate) == 0 {
		return nil, fmt.Errorf("policy channel client certificate and key are invalid")
	}
	config.publicKey = string(publicKey)
	config.ca = ca
	config.certificate = certificate
	return &config, nil
}

func (config *Config) httpClient() (*http.Client, func(), error) {
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	if len(config.ca) != 0 && !roots.AppendCertsFromPEM(config.ca) {
		return nil, nil, fmt.Errorf("policy channel CA file contains no certificates")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		RootCAs:      roots,
		Certificates: []tls.Certificate{config.certificate},
	}
	transport.MaxResponseHeaderBytes = 64 << 10
	return &http.Client{
		Transport: transport,
		Timeout:   45 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return fmt.Errorf("policy channel redirects are not allowed")
		},
	}, transport.CloseIdleConnections, nil
}

func validatePublicKey(raw []byte) error {
	block, rest := pem.Decode(raw)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return fmt.Errorf("expected one PEM public key")
	}
	var parsed any
	var err error
	switch block.Type {
	case "PUBLIC KEY":
		parsed, err = x509.ParsePKIXPublicKey(block.Bytes)
	case "RSA PUBLIC KEY":
		parsed, err = x509.ParsePKCS1PublicKey(block.Bytes)
	default:
		return fmt.Errorf("expected an RSA public key")
	}
	key, ok := parsed.(*rsa.PublicKey)
	if err != nil || !ok || key.N.BitLen() < 2048 {
		return fmt.Errorf("expected an RSA public key of at least 2048 bits")
	}
	return nil
}

func identifier(value string) bool {
	if value == "" || len(value) > 128 || value == "." || value == ".." {
		return false
	}
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-_.", r) {
			continue
		}
		return false
	}
	return true
}

func readRegular(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, fmt.Errorf("requires a regular file of at most %d bytes (no symlinks)", limit)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	info, err = file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, fmt.Errorf("requires a regular file of at most %d bytes", limit)
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, fmt.Errorf("file read failed or exceeds %d bytes", limit)
	}
	return raw, nil
}

func strictJSON(raw []byte, output any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return fmt.Errorf("trailing JSON")
	}
	return nil
}
