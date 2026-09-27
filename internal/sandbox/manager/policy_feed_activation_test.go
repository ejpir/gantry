package manager

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ejpir/gantry/api/managerapi"
	api "github.com/ejpir/gantry/api/policyservice"
	"github.com/ejpir/gantry/internal/policy"
	"github.com/ejpir/gantry/internal/policy/policytest"
	"github.com/ejpir/gantry/internal/sandbox/manager/runtimeowner"
)

func TestActivateManagedFeedWaitsForSignedGenerationAndSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GANTRY_HOME", filepath.Join(dir, "sandboxes"))
	a := newEnrollmentAuthority(t)
	snapshot := policytest.Signed(t, policy.Profile{})
	public, _ := pem.Decode([]byte(snapshot.PublicKey))
	key, err := x509.ParsePKCS1PublicKey(public.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	a.orgDER, err = x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	serverDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}},
		a.ca, &serverKey.PublicKey, a.caKey)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(a.ca)
	var published atomic.Bool
	var polls atomic.Int32
	service := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		polls.Add(1)
		if r.URL.Path != "/v1/feed" || r.TLS == nil || len(r.TLS.PeerCertificates) != 1 {
			http.Error(w, "client identity or path missing", http.StatusForbidden)
			return
		}
		if !published.Load() || r.Header.Get("If-None-Match") == `"g1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", `"g1"`)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"version": 1, "organization": "test-org", "generation": 1, "bundle": snapshot.Bundle,
		})
	}))
	service.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{{Certificate: [][]byte{serverDER, a.caDER}, PrivateKey: serverKey}},
		ClientAuth:   tls.RequireAndVerifyClientCert, ClientCAs: pool,
	}
	service.StartTLS()
	defer service.Close()
	feedURL := service.URL + "/v1/feed"

	m := newManagerService(nil)
	m.feedEnrollmentDir = filepath.Join(dir, "manager-state", "feed-enrollment")
	owner := runtimeowner.New(runtimeowner.Hooks{
		StopAdmission: m.stopAdmission, JoinRequests: m.joinRequests, JoinBackground: m.joinBackground,
	}, time.Second)
	m.feedOwner = owner
	if err := owner.SetLock(io.NopCloser(strings.NewReader(""))); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if err := owner.AddServer(&http.Server{Handler: m.ownedHandler(m.handler())}, listener, ""); err != nil {
		t.Fatal(err)
	}
	if err := owner.FeedsReady(nil); err != nil {
		t.Fatal(err)
	}
	if err := owner.StartServers(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := owner.Close(); err != nil {
			t.Error(err)
		}
	}()

	request := managerapi.PolicyFeedPrepareRequest{Host: "host-1", Organization: "test-org", Profile: "dev", URL: feedURL, PublicKeyFingerprint: pin(a.orgDER), CAFingerprint: pin(a.caDER)}
	var prepared managerapi.PolicyFeedPrepareResponse
	enrollmentRequest(t, m, "POST", "/v1/policy-feed/enrollment", request, http.StatusCreated, &prepared)
	files := a.filesFor(t, prepared.CSR, "test-org", "dev", feedURL)
	var status managerapi.PolicyFeedStatus
	enrollmentRequest(t, m, "POST", "/v1/policy-feed/enrollment/install", managerapi.PolicyFeedInstallRequest{ID: prepared.ID, Files: files}, http.StatusOK, &status)
	enrollmentRequest(t, m, "POST", "/v1/policy-feed/enrollment/activate", nil, http.StatusConflict, nil)
	if _, err := os.Lstat(filepath.Join(m.feedEnrollmentDir, "activated.json")); !os.IsNotExist(err) {
		t.Fatalf("unpublished feed was activated: %v", err)
	}
	if m.feedConfigured || m.organizationPolicy != nil {
		t.Fatal("unpublished policy claimed enforcement")
	}
	published.Store(true)
	enrollmentRequest(t, m, "POST", "/v1/policy-feed/enrollment/activate", nil, http.StatusOK, &status)
	if status.EnrollmentState != "configured" || status.AppliedGeneration != 1 || m.organizationPolicy == nil || m.organizationPolicy.Profile != "dev" || !bytes.Equal(m.organizationPolicy.Bundle, snapshot.Bundle) {
		t.Fatalf("feed did not apply before activation: %+v", status)
	}
	if polls.Load() < 2 {
		t.Fatal("activation did not poll the mTLS service")
	}
	if _, err := activatedEnrollmentConfig(m.feedEnrollmentDir); err != nil {
		t.Fatalf("automatic restart cannot load the activated feed: %v", err)
	}
	enrollmentRequest(t, m, "POST", "/v1/policy-feed/enrollment/activate", nil, http.StatusOK, &status)
	if status.AppliedGeneration != 1 {
		t.Fatal("retry changed the applied generation")
	}
	if err := os.WriteFile(filepath.Join(m.feedEnrollmentDir, api.PublicKeyFile), []byte("different"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := activatedEnrollmentConfig(m.feedEnrollmentDir); err == nil {
		t.Fatal("automatic restart trusted modified signing key")
	}
}
