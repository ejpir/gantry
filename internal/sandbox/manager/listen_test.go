package manager

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/ejpir/gantry/api/managerapi"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestParseListenSpec(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    listenSpec
		wantErr string
	}{
		{name: "bare path is unix", raw: "/tmp/manager.sock", want: listenSpec{network: "unix", address: "/tmp/manager.sock"}},
		{name: "unix scheme", raw: "unix:///tmp/manager.sock", want: listenSpec{network: "unix", address: "/tmp/manager.sock"}},
		{name: "tls scheme", raw: "tls://0.0.0.0:8443", want: listenSpec{network: "tls", address: "0.0.0.0:8443"}},
		{name: "tls all interfaces", raw: "tls://:8443", want: listenSpec{network: "tls", address: ":8443"}},
		{name: "tcp refused", raw: "tcp://0.0.0.0:8443", wantErr: "no insecure network mode"},
		{name: "http refused", raw: "http://0.0.0.0:8443", wantErr: "no insecure network mode"},
		{name: "unknown scheme", raw: "ftp://x", wantErr: "unknown listen scheme"},
		{name: "tls missing port", raw: "tls://host", wantErr: "ADDR:PORT"},
		{name: "empty", raw: "", wantErr: "empty"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			spec, err := parseListenSpec(test.raw)
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("parseListenSpec(%q) error = %v, want substring %q", test.raw, err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseListenSpec(%q): %v", test.raw, err)
			}
			if spec != test.want {
				t.Fatalf("parseListenSpec(%q) = %+v, want %+v", test.raw, spec, test.want)
			}
		})
	}
}

func TestResolveServePlanValidation(t *testing.T) {
	tests := []struct {
		name      string
		socket    string
		listens   []string
		tlsCert   string
		tlsKey    string
		selfSign  bool
		tokenFile string
		wantErr   string
	}{
		{name: "socket conflicts with listen", socket: "/tmp/a.sock", listens: []string{"unix:///tmp/b.sock"}, wantErr: "mutually exclusive"},
		{name: "tls requires token file", listens: []string{"tls://127.0.0.1:8443"}, selfSign: true, wantErr: "--token-file"},
		{name: "tls requires material", listens: []string{"tls://127.0.0.1:8443"}, tokenFile: "/tmp/t", wantErr: "--self-signed or both"},
		{name: "self-signed conflicts with cert", listens: []string{"tls://127.0.0.1:8443"}, selfSign: true, tlsCert: "/c", tlsKey: "/k", tokenFile: "/tmp/t", wantErr: "conflicts"},
		{name: "cert without key", listens: []string{"tls://127.0.0.1:8443"}, tlsCert: "/c", tokenFile: "/tmp/t", wantErr: "--self-signed or both"},
		{name: "tls flags rejected on unix", listens: []string{"unix:///tmp/a.sock"}, tokenFile: "/tmp/t", wantErr: "require a tls:// listener"},
		{name: "mixed unix and tls", listens: []string{"unix:///tmp/a.sock", "tls://127.0.0.1:8443"}, selfSign: true, tokenFile: "/tmp/t"},
		{name: "default plan is unix", wantErr: ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan, err := resolveServePlan(test.socket, test.listens, test.tlsCert, test.tlsKey, test.selfSign, test.tokenFile)
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("error = %v, want substring %q", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveServePlan: %v", err)
			}
			if len(plan.listeners) == 0 {
				t.Fatal("plan has no listeners")
			}
		})
	}
}

// newTestTokenAuth writes a token file and builds the authenticator with a
// captured audit log.
func newTestTokenAuth(t *testing.T, tokens ...string) (*tokenAuth, *bytes.Buffer, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tokens")
	writeTokenFile(t, path, tokens)
	var audit bytes.Buffer
	auth, err := newTokenAuth(path, log.New(&audit, "", 0))
	if err != nil {
		t.Fatalf("newTokenAuth: %v", err)
	}
	return auth, &audit, path
}

func writeTokenFile(t *testing.T, path string, tokens []string) {
	t.Helper()
	content := "# test tokens\n" + strings.Join(tokens, "\n") + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestTokenAuthMatrix(t *testing.T) {
	const (
		tokenOne = "0123456789abcdef0123456789abcdef"
		tokenTwo = "fedcba9876543210fedcba9876543210"
	)
	auth, _, _ := newTestTokenAuth(t, tokenOne, tokenTwo)
	service := newManagerService(stubLifecycle{})
	server := httptest.NewServer(service.authenticatedHandler(auth, log.New(io.Discard, "", 0)))
	client := server.Client()

	cases := []struct {
		name   string
		header string
		want   int
	}{
		{name: "no header", header: "", want: http.StatusForbidden},
		{name: "malformed scheme", header: "Basic " + tokenOne, want: http.StatusForbidden},
		{name: "bearer without token", header: "Bearer", want: http.StatusForbidden},
		{name: "empty token", header: "Bearer ", want: http.StatusForbidden},
		{name: "wrong token", header: "Bearer " + tokenTwo[:len(tokenTwo)-1] + "ff", want: http.StatusForbidden},
		{name: "first token", header: "Bearer " + tokenOne, want: http.StatusOK},
		{name: "second token", header: "Bearer " + tokenTwo, want: http.StatusOK},
		{name: "scheme case-insensitive", header: "bearer " + tokenOne, want: http.StatusOK},
		{name: "token plus junk is a different token", header: "Bearer " + tokenOne + "x", want: http.StatusForbidden},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			request, err := http.NewRequest(http.MethodGet, server.URL+"/v1/health", nil)
			if err != nil {
				t.Fatal(err)
			}
			if test.header != "" {
				request.Header.Set("Authorization", test.header)
			}
			response, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = response.Body.Close() }()
			if response.StatusCode != test.want {
				t.Fatalf("GET /v1/health with %q: status %d, want %d", test.header, response.StatusCode, test.want)
			}
		})
	}
}

func TestAuthenticatedHandlerProtectsEveryPath(t *testing.T) {
	auth, _, _ := newTestTokenAuth(t, "0123456789abcdef0123456789abcdef")
	service := newManagerService(stubLifecycle{})
	server := httptest.NewServer(service.authenticatedHandler(auth, log.New(io.Discard, "", 0)))
	// MUST 2: every path, including health and the OpenAPI contract, is
	// behind the token when the manager serves the network transport.
	for _, path := range []string{"/v1/health", "/v1/openapi.yaml", "/v1/sandboxes", "/v1/events"} {
		response, err := server.Client().Get(server.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusForbidden {
			t.Fatalf("GET %s without token: status %d, want 403", path, response.StatusCode)
		}
	}
}

func TestAuthenticationFailuresAreIndistinguishable(t *testing.T) {
	auth, _, _ := newTestTokenAuth(t, "0123456789abcdef0123456789abcdef")
	service := newManagerService(stubLifecycle{})
	server := httptest.NewServer(service.authenticatedHandler(auth, log.New(io.Discard, "", 0)))

	bodyFor := func(header string) string {
		request, err := http.NewRequest(http.MethodGet, server.URL+"/v1/health", nil)
		if err != nil {
			t.Fatal(err)
		}
		if header != "" {
			request.Header.Set("Authorization", header)
		}
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = response.Body.Close() }()
		var decoded managerapi.ErrorResponse
		if err := json.NewDecoder(response.Body).Decode(&decoded); err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != http.StatusForbidden {
			t.Fatalf("status %d, want 403", response.StatusCode)
		}
		return decoded.Error
	}
	missing := bodyFor("")
	wrong := bodyFor("Bearer wrongwrongwrongwrong")
	if missing != wrong {
		t.Fatalf("missing token error %q differs from wrong token error %q", missing, wrong)
	}
}

func TestTokenFileReload(t *testing.T) {
	const (
		tokenOld = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		tokenNew = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	)
	auth, _, path := newTestTokenAuth(t, tokenOld)
	if _, ok := auth.authenticate("Bearer " + tokenOld); !ok {
		t.Fatal("initial token rejected")
	}
	// Force a newer mtime; some filesystems have coarse granularity.
	writeTokenFile(t, path, []string{tokenNew})
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}
	auth.maybeReload()
	if _, ok := auth.authenticate("Bearer " + tokenOld); ok {
		t.Fatal("rotated-out token still accepted after reload")
	}
	if _, ok := auth.authenticate("Bearer " + tokenNew); !ok {
		t.Fatal("new token rejected after reload")
	}
	// A corrupt rewrite keeps the last-good set rather than revoking all.
	if err := os.WriteFile(path, []byte("short\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	later := future.Add(2 * time.Second)
	if err := os.Chtimes(path, later, later); err != nil {
		t.Fatal(err)
	}
	auth.maybeReload()
	if _, ok := auth.authenticate("Bearer " + tokenNew); !ok {
		t.Fatal("corrupt token file revoked the last-good set")
	}
}

func TestTokenFileValidation(t *testing.T) {
	if _, err := parseTokenFile([]byte("# only comments\n\n")); err == nil {
		t.Fatal("empty token file accepted")
	}
	if _, err := parseTokenFile([]byte("tiny\n")); err == nil {
		t.Fatal("short token accepted")
	}
	if _, err := parseTokenFile([]byte("has space inside token\n")); err == nil {
		t.Fatal("token with spaces accepted")
	}
	if hashes, err := parseTokenFile([]byte("# c\n0123456789abcdef\n")); err != nil || len(hashes) != 1 {
		t.Fatalf("valid file: hashes=%d err=%v", len(hashes), err)
	}
}

func TestMissingTokenFileFailsAtStartup(t *testing.T) {
	if _, err := newTokenAuth(filepath.Join(t.TempDir(), "absent"), log.New(io.Discard, "", 0)); err == nil {
		t.Fatal("missing token file did not fail startup")
	}
}

func TestMintToken(t *testing.T) {
	one, err := MintToken()
	if err != nil {
		t.Fatal(err)
	}
	two, err := MintToken()
	if err != nil {
		t.Fatal(err)
	}
	if one == two {
		t.Fatal("minted tokens collide")
	}
	if len(one) != 64 {
		t.Fatalf("minted token length %d, want 64 hex chars", len(one))
	}
}

func TestSelfSignedMaterialLifecycle(t *testing.T) {
	dir := t.TempDir()
	dns, ips := serveSANHosts([]listenSpec{{network: "tls", address: "192.0.2.10:8443"}})
	first, err := loadOrCreateSelfSigned(dir, dns, ips)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	for _, name := range []string{"ca.key", "ca.crt", "server.key", "server.crt"} {
		info, err := os.Lstat(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("expected %s: %v", name, err)
		}
		if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode %04o, want 0600", name, info.Mode().Perm())
		}
	}
	// Reload reuses material: the fingerprint a client pinned stays valid.
	second, err := loadOrCreateSelfSigned(dir, dns, ips)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if first.fingerprint != second.fingerprint {
		t.Fatal("fingerprint changed across reloads; client pinning would break")
	}
	if !strings.HasPrefix(first.fingerprint, "sha256:") {
		t.Fatalf("fingerprint %q lacks sha256: prefix", first.fingerprint)
	}

	// The server certificate verifies against the written CA and carries
	// the listen-address SAN.
	caPEM, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("ca.crt has no certificates")
	}
	serverPEM, err := os.ReadFile(filepath.Join(dir, "server.crt"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(serverPEM)
	if block == nil {
		t.Fatal("server.crt is not PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatalf("server certificate does not verify: %v", err)
	}
	foundIP := false
	for _, ip := range leaf.IPAddresses {
		if ip.String() == "192.0.2.10" {
			foundIP = true
		}
	}
	if !foundIP {
		t.Fatalf("listen-address SAN 192.0.2.10 missing from %v", leaf.IPAddresses)
	}
	if leaf.NotAfter.Before(time.Now().Add(9 * 365 * 24 * time.Hour)) {
		t.Fatalf("validity too short: %v", leaf.NotAfter)
	}

	// Corruption fails loudly with a repair hint — never a silent re-key.
	if err := os.WriteFile(filepath.Join(dir, "server.crt"), []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateSelfSigned(dir, dns, ips); err == nil || !strings.Contains(err.Error(), "delete") {
		t.Fatalf("corrupt material error = %v, want repair hint", err)
	}
}

func TestSelfSignedPartialMaterialRefused(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ca.crt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateSelfSigned(dir, nil, nil); err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("partial material error = %v, want incomplete hint", err)
	}
}

// freeTCPPort reserves and releases an ephemeral port for the TLS listener.
func freeTCPPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

// startTestServe runs serveWithOptions in the background and returns the
// captured audit log.
func startTestServe(t *testing.T, plan servePlan) (context.CancelFunc, *bytes.Buffer) {
	t.Helper()
	var audit bytes.Buffer
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- serveWithOptions(ctx, serveOptions{plan: plan, audit: log.New(&audit, "", 0)}, stubLifecycle{})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("serveWithOptions: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("serveWithOptions did not stop after cancel")
		}
	})
	return cancel, &audit
}

func waitForTLS(t *testing.T, address string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := tls.Dial("tcp", address, &tls.Config{InsecureSkipVerify: true}) // test-only client
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("TLS listener %s never came up", address)
}

func TestServeTLS(t *testing.T) {
	t.Setenv("GANTRY_HOME", filepath.Join(t.TempDir(), "sandboxes"))
	const token = "cafebabecafebabecafebabecafebabe"
	tokenPath := filepath.Join(t.TempDir(), "tokens")
	writeTokenFile(t, tokenPath, []string{token})
	port := freeTCPPort(t)
	address := fmt.Sprintf("127.0.0.1:%d", port)
	plan, err := resolveServePlan("", []string{"tls://" + address}, "", "", true, tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	_, audit := startTestServe(t, plan)
	waitForTLS(t, address)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // test-only client
		},
	}
	url := "https://" + address

	// No token: every path denied.
	response, err := client.Get(url + "/v1/health")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("health without token: %d, want 403", response.StatusCode)
	}

	// Valid token: health served over TLS.
	request, err := http.NewRequest(http.MethodGet, url+"/v1/health", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	var health map[string]any
	if err := json.NewDecoder(response.Body).Decode(&health); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || health["ok"] != true {
		t.Fatalf("health with token: status %d body %v", response.StatusCode, health)
	}

	// Mutating request with token reaches the handler (stub lifecycle).
	request, err = http.NewRequest(http.MethodPost, url+"/v1/sandboxes", strings.NewReader(`{"name":"dev","image":"alpine:latest"}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("create with token: %d, want 201", response.StatusCode)
	}

	// Plaintext HTTP against the TLS port is refused at the handshake.
	plainResponse, plainErr := (&http.Client{Timeout: 2 * time.Second}).Get("http://" + address + "/v1/health")
	if plainErr == nil {
		defer func() { _ = plainResponse.Body.Close() }()
		if plainResponse.StatusCode != http.StatusBadRequest {
			t.Fatalf("plaintext HTTP on TLS port: status %d, want handshake failure or 400", plainResponse.StatusCode)
		}
	}

	// Audit: mutations and denials recorded with fingerprints, never the
	// token value itself (MUST 3 and MUST 8).
	logText := audit.String()
	if strings.Contains(logText, token) {
		t.Fatal("audit log contains the raw token")
	}
	if !strings.Contains(logText, "tokenfp="+fingerprintToken(token)) {
		t.Fatalf("audit log lacks token fingerprint; got:\n%s", logText)
	}
	if !strings.Contains(logText, "result=denied") {
		t.Fatalf("audit log lacks denial record; got:\n%s", logText)
	}
	if !strings.Contains(logText, "method=POST path=/v1/sandboxes status=201") {
		t.Fatalf("audit log lacks mutation record; got:\n%s", logText)
	}
	if !strings.Contains(logText, "remote=127.0.0.1:") {
		t.Fatalf("audit log lacks remote address; got:\n%s", logText)
	}
}

func TestServeTLSRejectsPlaintextPlan(t *testing.T) {
	if _, err := resolveServePlan("", []string{"tcp://127.0.0.1:8443"}, "", "", true, "/tmp/t"); err == nil || !strings.Contains(err.Error(), "no insecure network mode") {
		t.Fatalf("plaintext plan error = %v", err)
	}
}

func TestMintedTokenRoundTrips(t *testing.T) {
	token, err := MintToken()
	if err != nil {
		t.Fatal(err)
	}
	auth, _, _ := newTestTokenAuth(t, token)
	if _, ok := auth.authenticate("Bearer " + token); !ok {
		t.Fatal("minted token not accepted")
	}
}
