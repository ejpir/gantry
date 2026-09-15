package policyfeed

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ejpir/gantry/internal/policy"
	"github.com/ejpir/gantry/internal/policy/policytest"
	"github.com/ejpir/gantry/internal/sandbox/localsec"
)

func TestLoadConfigPinsMutualTLSAndPolicyTrust(t *testing.T) {
	dir := t.TempDir()
	policySnapshot := policytest.Signed(t, policy.Profile{})
	if err := os.WriteFile(filepath.Join(dir, "org-public.pem"), []byte(policySnapshot.PublicKey), 0o644); err != nil {
		t.Fatal(err)
	}
	certificate, key := testClientCertificate(t)
	if err := os.WriteFile(filepath.Join(dir, "client.pem"), certificate, 0o644); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "client-key.pem")
	if err := os.WriteFile(keyPath, key, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := localsec.SecureRegularFile(keyPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.pem"), certificate, 0o644); err != nil {
		t.Fatal(err)
	}
	config := map[string]any{
		"version": 1, "organization": "test-org", "profile": "dev",
		"url": "https://policy.example.test/v1/desired", "public_key": "org-public.pem",
		"ca_file": "ca.pem", "client_certificate": "client.pem", "client_key": "client-key.pem",
		"poll_interval_seconds": 5,
	}
	raw, _ := json.Marshal(config)
	path := filepath.Join(dir, "feed.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Organization != "test-org" || loaded.Profile != "dev" || loaded.poll != 5*time.Second || len(loaded.certificate.Certificate) != 1 {
		t.Fatalf("loaded config = %#v", loaded)
	}

	if runtime.GOOS != "windows" {
		if err := os.Chmod(keyPath, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadConfig(path); err == nil || !strings.Contains(err.Error(), "not private") {
			t.Fatalf("insecure key error = %v", err)
		}
	}
}

func TestPolicyFeedClientUsesMutualTLS(t *testing.T) {
	dir := t.TempDir()
	certificatePEM, keyPEM := testClientCertificate(t)
	certificate, err := tls.X509KeyPair(certificatePEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	clientRoots := x509.NewCertPool()
	clientRoots.AppendCertsFromPEM(certificatePEM)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			t.Error("request did not supply a client certificate")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = &tls.Config{
		MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientRoots,
	}
	server.StartTLS()
	defer server.Close()

	policySnapshot := policytest.Signed(t, policy.Profile{})
	files := map[string][]byte{
		"org-public.pem": []byte(policySnapshot.PublicKey),
		"ca.pem":         certificatePEM, "client.pem": certificatePEM, "client-key.pem": keyPEM,
	}
	for name, data := range files {
		mode := os.FileMode(0o644)
		if name == "client-key.pem" {
			mode = 0o600
		}
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, mode); err != nil {
			t.Fatal(err)
		}
		if name == "client-key.pem" {
			if err := localsec.SecureRegularFile(path); err != nil {
				t.Fatal(err)
			}
		}
	}
	config := map[string]any{
		"version": 1, "organization": "test-org", "profile": "dev", "url": server.URL,
		"public_key": "org-public.pem", "ca_file": "ca.pem", "client_certificate": "client.pem", "client_key": "client-key.pem",
	}
	raw, _ := json.Marshal(config)
	configPath := filepath.Join(dir, "feed.json")
	if err := os.WriteFile(configPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	client, closeClient, err := loaded.httpClient()
	if err != nil {
		t.Fatal(err)
	}
	defer closeClient()
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d", response.StatusCode)
	}
}

func TestLoadConfigRejectsUnknownFieldsAndUntrustedTransport(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "feed.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"organization":"test","profile":"dev","url":"http://policy.example.test","public_key":"key","client_certificate":"cert","client_key":"private","unexpected":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil || !strings.Contains(err.Error(), "invalid policy channel configuration") {
		t.Fatalf("unknown-field error = %v", err)
	}
	if err := os.WriteFile(path, []byte(`{"version":1,"organization":"test","profile":"dev","url":"http://policy.example.test","public_key":"key","client_certificate":"cert","client_key":"private"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil || !strings.Contains(err.Error(), "URL must be HTTPS") {
		t.Fatalf("HTTP URL error = %v", err)
	}
}

func TestLoadConfigRejectsLegacySandboxScopedFeed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "feed.json")
	raw := []byte(`{"version":1,"organization":"test","sandbox":"dev","profile":"dev","url":"https://policy.example.test","public_key":"key","client_certificate":"cert","client_key":"private"}`)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil || !strings.Contains(err.Error(), "invalid policy channel configuration") {
		t.Fatalf("sandbox-scoped configuration error = %v", err)
	}
}

func testClientCertificate(t *testing.T) ([]byte, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "gantry-policy-client"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	private := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return certificate, private
}
