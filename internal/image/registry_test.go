package image

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gantry/internal/image/auth"
)

// fakeRegistry implements the 401 → token → 200 dance.
type fakeRegistry struct {
	srv        *httptest.Server
	manifest   []byte
	manDigest  string
	blobs      map[string][]byte
	wantUser   string // when set, the token endpoint requires this basic auth
	token      string
	gotAuth    []string // Authorization headers seen on the manifest/blob paths
	anonTokens int
}

func newFakeRegistry(t *testing.T, wantUser string) *fakeRegistry {
	t.Helper()
	r := &fakeRegistry{
		manifest:  []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:PLACEHOLDER","size":2},"layers":[]}`),
		blobs:     map[string][]byte{},
		wantUser:  wantUser,
		token:     "test-bearer-token",
	}
	r.manDigest = fmt.Sprintf("sha256:%x", sha256.Sum256(r.manifest))
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch {
		case strings.HasPrefix(req.URL.Path, "/token"):
			if r.wantUser != "" {
				u, p, ok := req.BasicAuth()
				if !ok || u != r.wantUser {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				_ = p
			} else {
				r.anonTokens++
			}
			w.Write([]byte(fmt.Sprintf(`{"token":%q,"expires_in":300}`, r.token)))
		case strings.Contains(req.URL.Path, "/manifests/") || strings.Contains(req.URL.Path, "/blobs/"):
			authz := req.Header.Get("Authorization")
			r.gotAuth = append(r.gotAuth, authz)
			if authz != "Bearer "+r.token {
				w.Header().Set("WWW-Authenticate",
					fmt.Sprintf(`Bearer realm="%s/token",service="test",scope="repository:library/app:pull"`, r.srv.URL))
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if strings.Contains(req.URL.Path, "/manifests/") {
				w.Header().Set("Docker-Content-Digest", r.manDigest)
				w.Write(r.manifest)
				return
			}
			// blob
			digest := req.URL.Path[strings.LastIndex(req.URL.Path, "/")+1:]
			if b, ok := r.blobs[digest]; ok {
				w.Write(b)
				return
			}
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func hostOf(u string) string {
	return strings.TrimPrefix(u, "http://")
}

func TestRegistryTokenDanceAnonymous(t *testing.T) {
	reg := newFakeRegistry(t, "")
	c := newRegistryClient(hostOf(reg.srv.URL), nil, t.Logf)
	b, digest, err := c.fetchManifest(context.Background(), "library/app", "latest")
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != string(reg.manifest) || digest != reg.manDigest {
		t.Errorf("got %s %s", b, digest)
	}
	// anonymous is not "no auth": the token endpoint was still consulted
	if reg.anonTokens != 1 {
		t.Errorf("anonymous token requests = %d, want 1", reg.anonTokens)
	}
	// first request unauthenticated, second with the bearer token
	if len(reg.gotAuth) != 2 || reg.gotAuth[0] != "" || reg.gotAuth[1] != "Bearer "+reg.token {
		t.Errorf("auth headers = %v", reg.gotAuth)
	}
}

func TestRegistryTokenDanceBasic(t *testing.T) {
	reg := newFakeRegistry(t, "realuser")
	cred := &auth.Credential{Username: "realuser", Secret: auth.Secret("pass")}
	c := newRegistryClient(hostOf(reg.srv.URL), cred, t.Logf)
	if _, _, err := c.fetchManifest(context.Background(), "library/app", "latest"); err != nil {
		t.Fatal(err)
	}
}

func TestRegistryStripsAuthOnCrossHostRedirect(t *testing.T) {
	reg := newFakeRegistry(t, "")
	// blob content lives on a DIFFERENT host (the CDN role)
	blobContent := []byte("blob-bytes")
	digest := fmt.Sprintf("sha256:%x", sha256.Sum256(blobContent))
	var cdnAuth []string
	cdn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		cdnAuth = append(cdnAuth, req.Header.Get("Authorization"))
		w.Write(blobContent)
	}))
	defer cdn.Close()
	// registry redirects the blob GET to the CDN
	reg.blobs[digest] = nil // mark known
	orig := reg.srv.Config.Handler
	_ = orig
	reg.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if strings.Contains(req.URL.Path, "/blobs/") && req.Header.Get("Authorization") == "Bearer "+reg.token {
			http.Redirect(w, req, cdn.URL+"/layer", http.StatusFound)
			return
		}
		// delegate everything else to a fresh registry handler
		newFakeRegistryHandler(reg)(w, req)
	})

	c := newRegistryClient(hostOf(reg.srv.URL), nil, t.Logf)
	dst := filepath.Join(t.TempDir(), "blob")
	if _, err := c.fetchBlob(context.Background(), "library/app", digest, dst); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(dst)
	if string(b) != string(blobContent) {
		t.Errorf("blob = %q", b)
	}
	if len(cdnAuth) != 1 || cdnAuth[0] != "" {
		t.Errorf("CDN saw Authorization headers %v — bearer token leaked cross-host", cdnAuth)
	}
}

// newFakeRegistryHandler re-derives the base handler for delegation.
func newFakeRegistryHandler(r *fakeRegistry) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		switch {
		case strings.HasPrefix(req.URL.Path, "/token"):
			r.anonTokens++
			w.Write([]byte(fmt.Sprintf(`{"token":%q,"expires_in":300}`, r.token)))
		case strings.Contains(req.URL.Path, "/manifests/") || strings.Contains(req.URL.Path, "/blobs/"):
			authz := req.Header.Get("Authorization")
			r.gotAuth = append(r.gotAuth, authz)
			if authz != "Bearer "+r.token {
				w.Header().Set("WWW-Authenticate",
					fmt.Sprintf(`Bearer realm="%s/token",service="test",scope="repository:library/app:pull"`, r.srv.URL))
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("Docker-Content-Digest", r.manDigest)
			w.Write(r.manifest)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

func TestParseRef(t *testing.T) {
	cases := []struct{ in, reg, repo, tag, digest string }{
		{"debian", "registry-1.docker.io", "library/debian", "latest", ""},
		{"debian:bookworm-slim", "registry-1.docker.io", "library/debian", "bookworm-slim", ""},
		{"docker.io/user/app", "registry-1.docker.io", "user/app", "latest", ""},
		{"index.docker.io/user/app:1", "registry-1.docker.io", "user/app", "1", ""},
		{"ghcr.io/org/app", "ghcr.io", "org/app", "latest", ""},
		{"ghcr.io/org/app@sha256:" + strings.Repeat("a", 64), "ghcr.io", "org/app", "", "sha256:" + strings.Repeat("a", 64)},
		{"localhost:5000/app:dev", "localhost:5000", "app", "dev", ""},
		{"127.0.0.1:5000/ns/app", "127.0.0.1:5000", "ns/app", "latest", ""},
	}
	for _, c := range cases {
		r, err := ParseRef(c.in)
		if err != nil {
			t.Errorf("%s: %v", c.in, err)
			continue
		}
		if r.Registry != c.reg || r.Repo != c.repo || r.Tag != c.tag || r.Digest != c.digest {
			t.Errorf("%s → %+v, want %s/%s:%s@%s", c.in, r, c.reg, c.repo, c.tag, c.digest)
		}
	}
	for _, bad := range []string{"", "@sha256:xyz", "reg.io//app", "a/../b"} {
		if _, err := ParseRef(bad); err == nil {
			t.Errorf("%q should fail", bad)
		}
	}
}

// redaction: a debug-mode pull must not leak the secret or the token
// through the logging path.
func TestRegistryLogRedaction(t *testing.T) {
	reg := newFakeRegistry(t, "realuser")
	var logs strings.Builder
	cred := &auth.Credential{Username: "realuser", Secret: auth.Secret("supersecret")}
	c := newRegistryClient(hostOf(reg.srv.URL), cred, func(f string, a ...any) {
		fmt.Fprintf(&logs, f+"\n", a...)
	})
	if _, _, err := c.fetchManifest(context.Background(), "library/app", "latest"); err != nil {
		t.Fatal(err)
	}
	out := logs.String()
	if strings.Contains(out, "supersecret") || strings.Contains(out, reg.token) {
		t.Errorf("logs leaked credentials:\n%s", out)
	}
}
