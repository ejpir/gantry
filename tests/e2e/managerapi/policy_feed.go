package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ejpir/gantry/api/managerapi"
	"github.com/ejpir/gantry/internal/sandbox/localsec"
)

const policyFeedGeneration = 1

type policyFeedHarness struct {
	server     *httptest.Server
	configPath string
	bundle     []byte

	mu      sync.RWMutex
	enabled bool
	applied chan struct{}
	once    sync.Once
}

func setupPolicyFeed(ctx context.Context, repo string, env []string, gantry, work string) (*policyFeedHarness, error) {
	policyDir := filepath.Join(work, "policy-feed-policy")
	if err := runCommand(ctx, repo, env, gantry, "policy", "generate", "-out", policyDir,
		"-organization", "manager-e2e", "-profile", "developer", "-ttl", "1h"); err != nil {
		return nil, fmt.Errorf("generate feed policy: %w", err)
	}
	bundle, err := os.ReadFile(filepath.Join(policyDir, "bundle.tar.gz"))
	if err != nil {
		return nil, err
	}

	caCert, caKey, caPEM, err := newPolicyFeedCA()
	if err != nil {
		return nil, err
	}
	serverCert, _, err := issuePolicyFeedCertificate(caCert, caKey, "policy-feed-server", true)
	if err != nil {
		return nil, err
	}
	clientCert, clientKey, err := issuePolicyFeedCertificate(caCert, caKey, "gantry-manager", false)
	if err != nil {
		return nil, err
	}
	clientRoots := x509.NewCertPool()
	if !clientRoots.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("construct policy-feed client CA pool")
	}
	harness := &policyFeedHarness{bundle: bundle, applied: make(chan struct{})}
	harness.server = httptest.NewUnstartedServer(http.HandlerFunc(harness.handle))
	harness.server.TLS = &tls.Config{
		MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{serverCert},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientRoots,
	}
	harness.server.StartTLS()

	feedDir := filepath.Join(work, "policy-feed")
	if err := os.MkdirAll(feedDir, 0o700); err != nil {
		harness.Close()
		return nil, err
	}
	files := map[string]struct {
		data []byte
		mode os.FileMode
	}{
		"ca.pem":         {caPEM, 0o644},
		"client.pem":     {pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCert.Certificate[0]}), 0o644},
		"client-key.pem": {clientKey, 0o600},
	}
	for name, file := range files {
		path := filepath.Join(feedDir, name)
		if err := os.WriteFile(path, file.data, file.mode); err != nil {
			harness.Close()
			return nil, err
		}
		if name == "client-key.pem" {
			if err := localsec.SecureRegularFile(path); err != nil {
				harness.Close()
				return nil, err
			}
		}
	}
	config := map[string]any{
		"version": 1, "organization": "manager-e2e",
		"profile": "developer", "url": harness.server.URL,
		"public_key": filepath.Join(policyDir, "public.pem"), "ca_file": "ca.pem",
		"client_certificate": "client.pem", "client_key": "client-key.pem",
		"poll_interval_seconds": 5,
	}
	raw, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		harness.Close()
		return nil, err
	}
	harness.configPath = filepath.Join(feedDir, "feed.json")
	if err := os.WriteFile(harness.configPath, append(raw, '\n'), 0o600); err != nil {
		harness.Close()
		return nil, err
	}
	return harness, nil
}

func (harness *policyFeedHarness) handle(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "client certificate required", http.StatusForbidden)
		return
	}
	if r.Header.Get("X-Gantry-Policy-Generation") == strconv.Itoa(policyFeedGeneration) && len(r.Header.Get("X-Gantry-Policy-Digest")) == 64 {
		harness.once.Do(func() { close(harness.applied) })
	}
	harness.mu.RLock()
	enabled := harness.enabled
	harness.mu.RUnlock()
	if !enabled || r.Header.Get("If-None-Match") == `"generation-1"` {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("ETag", `"generation-1"`)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"version": 1, "organization": "manager-e2e",
		"generation": policyFeedGeneration, "bundle": harness.bundle,
	})
}

func (harness *policyFeedHarness) Publish() {
	harness.mu.Lock()
	harness.enabled = true
	harness.mu.Unlock()
}

func (harness *policyFeedHarness) WaitApplied(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-harness.applied:
		return nil
	}
}

func (harness *policyFeedHarness) Close() {
	if harness != nil && harness.server != nil {
		harness.server.Close()
	}
}

func newPolicyFeedCA() (*x509.Certificate, *rsa.PrivateKey, []byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, err
	}
	certificate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "manager-e2e-policy-feed-ca"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, err
	}
	return certificate, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

func issuePolicyFeedCertificate(ca *x509.Certificate, caKey *rsa.PrivateKey, commonName string, server bool) (tls.Certificate, []byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	certificate := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: commonName},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	if server {
		certificate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		certificate.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	} else {
		certificate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, certificate, ca, &key.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	pair, err := tls.X509KeyPair(certificatePEM, keyPEM)
	return pair, keyPEM, err
}

func testPolicyFeedRollout(ctx context.Context, client *apiClient, harness *policyFeedHarness, sandboxName string, createBody []byte) error {
	peerName := sandboxName + "-org-peer"
	if len(peerName) > 64 {
		peerName = sandboxName[:64-len("-org-peer")] + "-org-peer"
	}
	var peerRequest map[string]any
	if err := json.Unmarshal(createBody, &peerRequest); err != nil {
		return err
	}
	peerRequest["name"] = peerName
	peerBody, err := json.Marshal(peerRequest)
	if err != nil {
		return err
	}
	peerCreated := true
	defer func() {
		if !peerCreated {
			return
		}
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		_, _, _, _ = client.do(cleanup, http.MethodDelete, "/v1/sandboxes/"+peerName, nil, nil)
	}()
	status, body, _, err := client.do(ctx, http.MethodPost, "/v1/sandboxes", peerBody, map[string]string{"Idempotency-Key": "policy-peer-create-1"})
	if err != nil {
		return err
	}
	if err := expectStatus(status, body, http.StatusCreated); err != nil {
		return fmt.Errorf("create policy-feed peer: %w", err)
	}

	before := make(map[string]managerapi.Sandbox, 2)
	for _, name := range []string{sandboxName, peerName} {
		status, body, _, err = client.do(ctx, http.MethodGet, "/v1/sandboxes/"+name, nil, nil)
		if err != nil {
			return err
		}
		if err := expectStatus(status, body, http.StatusOK); err != nil {
			return err
		}
		var current managerapi.Sandbox
		if err := json.Unmarshal(body, &current); err != nil {
			return err
		}
		before[name] = current
	}

	harness.Publish()
	if err := harness.WaitApplied(ctx); err != nil {
		return fmt.Errorf("wait for aggregate feed acknowledgement: %w", err)
	}
	for _, name := range []string{sandboxName, peerName} {
		status, body, _, err = client.do(ctx, http.MethodGet, "/v1/sandboxes/"+name+"/policy", nil, nil)
		if err != nil {
			return err
		}
		if err := expectStatus(status, body, http.StatusOK); err != nil {
			return err
		}
		var current managerapi.OrganizationPolicy
		if err := json.Unmarshal(body, &current); err != nil {
			return err
		}
		if !current.Managed || current.Info == nil || current.Info.Organization != "manager-e2e" || current.Info.Profile != "developer" {
			return fmt.Errorf("unexpected feed policy for %s: %+v", name, current)
		}
		status, body, _, err = client.do(ctx, http.MethodGet, "/v1/sandboxes/"+name, nil, nil)
		if err != nil {
			return err
		}
		if err := expectStatus(status, body, http.StatusOK); err != nil {
			return err
		}
		var after managerapi.Sandbox
		if err := json.Unmarshal(body, &after); err != nil {
			return err
		}
		if after.State != "running" || after.PID == 0 || after.PID != before[name].PID {
			return fmt.Errorf("organization-wide policy feed changed %s during live update: before=%+v after=%+v", name, before[name], after)
		}
		if err := expectExec(ctx, client, name, []byte(`{"argv":["/bin/sh","-c","printf policy-feed"]}`), 0, "policy-feed"); err != nil {
			return err
		}
	}

	clear, _ := json.Marshal(managerapi.OrganizationPolicyRequest{Clear: true})
	status, body, _, err = client.do(ctx, http.MethodPut, "/v1/sandboxes/"+sandboxName+"/policy", clear, map[string]string{"Idempotency-Key": "policy-clear-refused-1"})
	if err != nil {
		return err
	}
	if status != http.StatusConflict || !strings.Contains(string(body), "organization-wide policy feed controls") {
		return fmt.Errorf("organization-wide policy clear was not refused: status=%d body=%s", status, body)
	}

	status, body, _, err = client.do(ctx, http.MethodDelete, "/v1/sandboxes/"+peerName, nil, map[string]string{"Idempotency-Key": "policy-peer-delete-1"})
	if err != nil {
		return err
	}
	if err := expectStatus(status, body, http.StatusOK); err != nil {
		return err
	}
	peerCreated = false
	return nil
}
