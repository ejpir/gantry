package manager

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ejpir/gantry/api/managerapi"
	api "github.com/ejpir/gantry/api/policyservice"
	"github.com/ejpir/gantry/internal/policyfeed"
)

func enrollmentRequest(t *testing.T, m *managerService, method, path string, body any, want int, out any) {
	t.Helper()
	var raw []byte
	if body != nil {
		var err error
		raw, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	w := httptest.NewRecorder()
	m.handler().ServeHTTP(w, httptest.NewRequest(method, path, bytes.NewReader(raw)))
	if w.Code != want {
		t.Fatalf("%s %s status %d want %d: %s", method, path, w.Code, want, w.Body.String())
	}
	if out != nil && json.NewDecoder(w.Body).Decode(out) != nil {
		t.Fatalf("invalid response: %s", w.Body.String())
	}
}

type enrollmentAuthority struct {
	orgDER, caDER []byte
	ca            *x509.Certificate
	caKey         *rsa.PrivateKey
}

func newEnrollmentAuthority(t *testing.T) enrollmentAuthority {
	t.Helper()
	orgKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	orgDER, err := x509.MarshalPKIXPublicKey(&orgKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	return enrollmentAuthority{orgDER: orgDER, caDER: caDER, ca: ca, caKey: caKey}
}

func (a enrollmentAuthority) files(t *testing.T, csrPEM string) map[string]string {
	t.Helper()
	csrBlock, _ := pem.Decode([]byte(csrPEM))
	if csrBlock == nil {
		t.Fatal("missing CSR")
	}
	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	clientTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: csr.Subject.CommonName, Organization: []string{"acme"}}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	certDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, a.ca, csr.PublicKey, a.caKey)
	if err != nil {
		t.Fatal(err)
	}
	config := `{"version":1,"organization":"acme","profile":"developer","url":"https://policy.example.test/v1/feed","public_key":"org-public.pem","ca_file":"ca.pem","client_certificate":"host.pem","client_key":"host-key.pem"}`
	return map[string]string{
		api.FeedConfigFile: config,
		api.HostCertFile:   string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})),
		api.CAFile:         string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.caDER})),
		api.PublicKeyFile:  string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: a.orgDER})),
	}
}

func TestManagerManagedFeedEnrollment(t *testing.T) {
	dir := t.TempDir()
	m := newManagerService(nil)
	m.feedEnrollmentDir = filepath.Join(dir, "feed-enrollment")
	a := newEnrollmentAuthority(t)
	request := managerapi.PolicyFeedPrepareRequest{Host: "host-1", Organization: "acme", Profile: "developer", URL: "https://policy.example.test/v1/feed", PublicKeyFingerprint: pin(a.orgDER), CAFingerprint: pin(a.caDER)}
	var prepared managerapi.PolicyFeedPrepareResponse
	enrollmentRequest(t, m, "POST", "/v1/policy-feed/enrollment", request, 201, &prepared)
	if prepared.ID == "" || !strings.Contains(prepared.CSR, "BEGIN CERTIFICATE REQUEST") {
		t.Fatalf("invalid preparation: %+v", prepared)
	}
	if err := allowAutomaticManager(dir); err != nil {
		t.Fatal("pending CSR blocked a restart before enrollment:", err)
	}
	var retry managerapi.PolicyFeedPrepareResponse
	enrollmentRequest(t, m, "POST", "/v1/policy-feed/enrollment", request, 200, &retry)
	if retry != prepared {
		t.Fatalf("retry changed CSR: %+v", retry)
	}
	request.Host = "another-host"
	enrollmentRequest(t, m, "POST", "/v1/policy-feed/enrollment", request, 409, nil)
	files := a.files(t, prepared.CSR)
	install := managerapi.PolicyFeedInstallRequest{ID: prepared.ID, Files: files}
	var status managerapi.PolicyFeedStatus
	enrollmentRequest(t, m, "GET", "/v1/policy-feed/enrollment", nil, 200, &status)
	if status.EnrollmentState != "awaiting-enrollment" || status.ConfigPath != "" {
		t.Fatalf("premature activation: %+v", status)
	}
	wrong := a.files(t, prepared.CSR)
	wrong[api.PublicKeyFile] = files[api.CAFile]
	enrollmentRequest(t, m, "POST", "/v1/policy-feed/enrollment/install", managerapi.PolicyFeedInstallRequest{ID: prepared.ID, Files: wrong}, 422, nil)
	if _, err := os.Stat(filepath.Join(m.feedEnrollmentDir, api.FeedConfigFile)); !os.IsNotExist(err) {
		t.Fatalf("invalid trust created config: %v", err)
	}
	// A signed certificate for another key is refused before any file is staged.
	other := newManagerService(nil)
	other.feedEnrollmentDir = filepath.Join(t.TempDir(), "feed-enrollment")
	var otherPrepared managerapi.PolicyFeedPrepareResponse
	enrollmentRequest(t, other, "POST", "/v1/policy-feed/enrollment", managerapi.PolicyFeedPrepareRequest{Host: "host-1", Organization: "acme", Profile: "developer", URL: request.URL, PublicKeyFingerprint: pin(a.orgDER), CAFingerprint: pin(a.caDER)}, 201, &otherPrepared)
	otherCert := a.files(t, otherPrepared.CSR)[api.HostCertFile]
	files[api.HostCertFile] = otherCert
	enrollmentRequest(t, m, "POST", "/v1/policy-feed/enrollment/install", install, 422, nil)
	files[api.HostCertFile] = a.files(t, prepared.CSR)[api.HostCertFile]
	enrollmentRequest(t, m, "POST", "/v1/policy-feed/enrollment/install", install, 200, &status)
	if status.EnrollmentState != "restart-required" || status.ConfigPath == "" {
		t.Fatalf("not staged: %+v", status)
	}
	if _, err := policyfeed.LoadConfig(status.ConfigPath); err != nil {
		t.Fatalf("staged feed invalid: %v", err)
	}
	enrollmentRequest(t, m, "POST", "/v1/policy-feed/enrollment/install", install, 200, &status)
	if status.EnrollmentState != "restart-required" {
		t.Fatalf("retry unstaged feed: %+v", status)
	}
	keyPath := filepath.Join(m.feedEnrollmentDir, api.HostKeyFile)
	key, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains([]byte(status.ConfigPath), key) || bytes.Contains([]byte(prepared.CSR), key) {
		t.Fatal("private key was exposed")
	}
	if info, err := os.Stat(keyPath); err != nil || info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("host key not private: %v %v", info, err)
	}
	if err := allowAutomaticManager(dir); err == nil {
		t.Fatal("staged feed allowed ungoverned automatic restart")
	}
	if err := checkStagedFeedPath(m.feedEnrollmentDir, ""); err == nil {
		t.Fatal("staged feed allowed restart without its config")
	}
	if err := checkStagedFeedPath(m.feedEnrollmentDir, filepath.Join(dir, "other.json")); err == nil {
		t.Fatal("staged feed allowed restart with another config")
	}
	if err := checkStagedFeedPath(m.feedEnrollmentDir, status.ConfigPath); err != nil {
		t.Fatal("correct feed path rejected:", err)
	}
}

func TestManagerFeedInstallationRejectsSymlink(t *testing.T) {
	m := newManagerService(nil)
	m.feedEnrollmentDir = filepath.Join(t.TempDir(), "feed-enrollment")
	a := newEnrollmentAuthority(t)
	var prepared managerapi.PolicyFeedPrepareResponse
	enrollmentRequest(t, m, "POST", "/v1/policy-feed/enrollment", managerapi.PolicyFeedPrepareRequest{Host: "host-1", Organization: "acme", Profile: "developer", URL: "https://policy.example.test/v1/feed", PublicKeyFingerprint: pin(a.orgDER), CAFingerprint: pin(a.caDER)}, 201, &prepared)
	if err := os.Symlink(filepath.Join(t.TempDir(), "outside"), filepath.Join(m.feedEnrollmentDir, api.CAFile)); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	enrollmentRequest(t, m, "POST", "/v1/policy-feed/enrollment/install", managerapi.PolicyFeedInstallRequest{ID: prepared.ID, Files: a.files(t, prepared.CSR)}, 409, nil)
}
