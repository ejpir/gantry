package image

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ejpir/gantry/internal/image/auth"
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
		manifest: []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:PLACEHOLDER","size":2},"layers":[]}`),
		blobs:    map[string][]byte{},
		wantUser: wantUser,
		token:    "test-bearer-token",
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
			_, _ = fmt.Fprintf(w, `{"token":%q,"expires_in":300}`, r.token)
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
				_, _ = w.Write(r.manifest)
				return
			}
			// blob
			digest := req.URL.Path[strings.LastIndex(req.URL.Path, "/")+1:]
			if b, ok := r.blobs[digest]; ok {
				_, _ = w.Write(b)
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

func TestRegistryRejectsShortLayerDigestWithProgress(t *testing.T) {
	reg := newFakeRegistry(t, "")
	config := []byte(`{"architecture":"amd64","os":"linux","config":{}}`)
	configDigest := fmt.Sprintf("sha256:%x", sha256.Sum256(config))
	reg.blobs[configDigest] = config
	reg.manifest = []byte(fmt.Sprintf(`{"schemaVersion":2,"config":{"digest":%q,"size":%d},"layers":[{"digest":"sha256:x","size":1}]}`,
		configDigest, len(config)))
	reg.manDigest = fmt.Sprintf("sha256:%x", sha256.Sum256(reg.manifest))

	progressCalled := false
	_, err := loadRegistry(context.Background(), hostOf(reg.srv.URL)+"/library/app:latest", "amd64", auth.Resolve(),
		func(string, ...any) { progressCalled = true })
	if err == nil || !strings.Contains(err.Error(), "layer 1 descriptor: invalid SHA-256 digest length") {
		t.Fatalf("short layer digest error = %v", err)
	}
	if progressCalled {
		t.Fatal("progress callback ran before manifest descriptors were validated")
	}
}

func TestFetchBlobRejectsMalformedDescriptorBeforeRequest(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests++ }))
	defer server.Close()
	client := newRegistryClient(hostOf(server.URL), nil, nil)
	_, err := client.fetchBlob(context.Background(), "library/app", descriptor{Digest: "sha256:../../manifests/latest", Size: 1}, filepath.Join(t.TempDir(), "blob"))
	if err == nil || !strings.Contains(err.Error(), "invalid blob descriptor") {
		t.Fatalf("malformed descriptor error = %v", err)
	}
	if requests != 0 {
		t.Fatalf("malformed descriptor made %d registry requests", requests)
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
		_, _ = w.Write(blobContent)
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
	if _, err := c.fetchBlob(context.Background(), "library/app", descriptor{Digest: digest, Size: int64(len(blobContent))}, dst); err != nil {
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
			_, _ = fmt.Fprintf(w, `{"token":%q,"expires_in":300}`, r.token)
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
			_, _ = w.Write(r.manifest)
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
	for _, bad := range []string{
		"", "@sha256:xyz", "reg.io//app", "a/../b",
		"reg.io/app@sha256:" + strings.Repeat("g", 64),
		"reg.io/app@sha256:" + strings.Repeat("a", 31) + "/" + strings.Repeat("a", 32),
	} {
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

// ---------------- fake multi-arch registry (no auth) ----------------

// fakeIndexRegistry serves one tag pointing at an index with one
// platform manifest, plus its config and one layer. blobGets counts
// blob requests so tests can prove a cache hit downloaded nothing.
type fakeIndexRegistry struct {
	srv            *httptest.Server
	repo           string
	indexDigest    string
	manifestDigest string
	manifestGets   int
	manifestHeads  int
	blobGets       int
	headerDigest   string // when set, overrides Docker-Content-Digest on GET
	oversizeBlobs  bool   // serve blobs larger than their descriptor
	denyStatus     int    // when set, manifest requests get this status (proxy block)
}

func newFakeIndexRegistry(t *testing.T, arch string) *fakeIndexRegistry {
	t.Helper()
	r := &fakeIndexRegistry{repo: "library/app"}

	var lb strings.Builder
	tw := tar.NewWriter(&lb)
	data := []byte("hello")
	if err := tw.WriteHeader(&tar.Header{Name: "hello.txt", Mode: 0o644, Size: int64(len(data)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	_, _ = tw.Write(data)
	_ = tw.Close()
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write([]byte(lb.String()))
	_ = zw.Close()
	layer := gz.Bytes()
	layerDigest := fmt.Sprintf("sha256:%x", sha256.Sum256(layer))

	cfg := fmt.Sprintf(`{"architecture":%q,"os":"linux","config":{"Env":["PATH=/usr/bin"]}}`, arch)
	cfgDigest := fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(cfg)))

	manifest := fmt.Sprintf(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json",
"config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":%q,"size":%d},
"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":%q,"size":%d}]}`,
		cfgDigest, len(cfg), layerDigest, len(layer))
	r.manifestDigest = fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(manifest)))

	index := fmt.Sprintf(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json",
"manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":%q,"size":%d,
"platform":{"architecture":%q,"os":"linux"}}]}`, r.manifestDigest, len(manifest), arch)
	r.indexDigest = fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(index)))

	blobs := map[string][]byte{cfgDigest: []byte(cfg), layerDigest: layer}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		p := strings.TrimPrefix(req.URL.Path, "/v2/"+r.repo+"/")
		switch {
		case strings.HasPrefix(p, "manifests/"):
			if req.Method == http.MethodHead {
				r.manifestHeads++
			} else {
				r.manifestGets++
			}
			if r.denyStatus != 0 {
				http.Error(w, "proxy block page", r.denyStatus)
				return
			}
			ref := strings.TrimPrefix(p, "manifests/")
			var body, digest string
			switch ref {
			case "latest":
				body, digest = index, r.indexDigest
			case r.manifestDigest:
				body, digest = manifest, r.manifestDigest
			default:
				http.Error(w, "unknown manifest", 404)
				return
			}
			if r.headerDigest != "" && req.Method == "GET" {
				digest = r.headerDigest
			}
			w.Header().Set("Docker-Content-Digest", digest)
			w.Header().Set("Content-Type", "application/vnd.oci.image.index.v1+json")
			_, _ = w.Write([]byte(body))
		case strings.HasPrefix(p, "blobs/"):
			r.blobGets++
			b, ok := blobs[strings.TrimPrefix(p, "blobs/")]
			if !ok {
				http.Error(w, "unknown blob", 404)
				return
			}
			if r.oversizeBlobs {
				b = append(b, 0x41) // one byte beyond the descriptor
			}
			_, _ = w.Write(b)
		default:
			http.Error(w, "unexpected", 404)
		}
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *fakeIndexRegistry) ref() string {
	return strings.TrimPrefix(r.srv.URL, "http://") + "/" + r.repo + ":latest"
}

// review4 #3+#4: a multi-arch pull must hit the cache on the next
// resolve (HEAD compares the INDEX digest against Meta.RefDigest), and
// the cache must be keyed per arch.
func TestResolvePreferCachedSkipsRegistryFreshness(t *testing.T) {
	reg := newFakeIndexRegistry(t, "arm64")
	st := NewStore(t.TempDir())

	first, err := Resolve(reg.ref(), "arm64", st, nil)
	if err != nil {
		t.Fatal(err)
	}
	gets, heads, blobs := reg.manifestGets, reg.manifestHeads, reg.blobGets
	reg.denyStatus = http.StatusForbidden

	cached, err := ResolvePreferCached(reg.ref(), "arm64", st, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !cached.Cached || cached.Digest != first.Digest {
		t.Fatalf("preferred cache result = %+v, want digest %s", cached, first.Digest)
	}
	if reg.manifestGets != gets || reg.manifestHeads != heads || reg.blobGets != blobs {
		t.Fatalf("preferred cache made registry requests: manifests GET %d->%d HEAD %d->%d blobs %d->%d",
			gets, reg.manifestGets, heads, reg.manifestHeads, blobs, reg.blobGets)
	}
}

func TestResolveCachedOnlyMissDoesNotContactRegistry(t *testing.T) {
	reg := newFakeIndexRegistry(t, "arm64")
	_, err := ResolveCachedOnly(reg.ref(), "arm64", NewStore(t.TempDir()), nil)
	if err == nil || !strings.Contains(err.Error(), "gantry image pull") {
		t.Fatalf("cached-only miss error = %v, want pull instruction", err)
	}
	if reg.manifestGets != 0 || reg.manifestHeads != 0 || reg.blobGets != 0 {
		t.Fatalf("cached-only miss contacted registry: GETs=%d HEADs=%d blobs=%d",
			reg.manifestGets, reg.manifestHeads, reg.blobGets)
	}
}

func TestResolvePreferCachedMissPulls(t *testing.T) {
	reg := newFakeIndexRegistry(t, "arm64")
	resolved, err := ResolvePreferCached(reg.ref(), "arm64", NewStore(t.TempDir()), nil)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Cached {
		t.Fatal("cache miss incorrectly reported a cached result")
	}
	if reg.manifestGets == 0 || reg.blobGets == 0 {
		t.Fatalf("cache miss did not pull: manifest GETs=%d blobs=%d", reg.manifestGets, reg.blobGets)
	}
}

func TestCacheHitMultiArch(t *testing.T) {
	reg := newFakeIndexRegistry(t, "arm64")
	st := NewStore(t.TempDir())

	r1, err := Resolve(reg.ref(), "arm64", st, nil)
	if err != nil {
		t.Fatal(err)
	}
	if r1.Cached {
		t.Error("first pull must not report Cached")
	}
	blobsAfterFirst := reg.blobGets

	r2, err := Resolve(reg.ref(), "arm64", st, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !r2.Cached {
		t.Error("second resolve of an unchanged tag must be a cache hit")
	}
	if r2.Digest != r1.Digest {
		t.Errorf("digest changed between resolves: %s vs %s", r1.Digest, r2.Digest)
	}
	if reg.blobGets != blobsAfterFirst {
		t.Errorf("cache hit downloaded %d blobs — HEAD compare never matched (RefDigest not recorded?)",
			reg.blobGets-blobsAfterFirst)
	}

	// arch keying: same ref, different guest arch → miss → pull →
	// the fake registry has no amd64 manifest, proving the lookup
	// did NOT reuse the arm64 slot
	if _, err := Resolve(reg.ref(), "amd64", st, nil); err == nil ||
		!strings.Contains(err.Error(), "no manifest for linux/amd64") {
		t.Errorf("amd64 resolve: err = %v, want no-manifest (arm64 cache must not leak across arches)", err)
	}
}

// review4 #5: the manifest digest is the content hash; a disagreeing
// Docker-Content-Digest header is an error, not a cache key.
func TestManifestDigestHeaderMismatch(t *testing.T) {
	reg := newFakeIndexRegistry(t, "arm64")
	reg.headerDigest = "sha256:" + strings.Repeat("0", 64)
	if _, err := Resolve(reg.ref(), "arm64", NewStore(t.TempDir()), nil); err == nil ||
		!strings.Contains(err.Error(), "does not match content") {
		t.Errorf("err = %v, want a digest-mismatch error", err)
	}
}

// review4 smaller: blob downloads are capped by the descriptor size.
func TestBlobLargerThanDescriptor(t *testing.T) {
	reg := newFakeIndexRegistry(t, "arm64")
	reg.oversizeBlobs = true
	_, err := Resolve(reg.ref(), "arm64", NewStore(t.TempDir()), nil)
	if err == nil || !strings.Contains(err.Error(), "larger than its descriptor") {
		t.Errorf("err = %v, want a descriptor-size error", err)
	}
}

// A registry (or filtering proxy) that ANSWERS the freshness HEAD with an
// HTTP error — e.g. a Zscaler 403 block page — is a refusal, not an
// outage: Resolve must fail loudly rather than silently boot the stale
// cached image.
func TestCacheFallbackRefusedOnHTTPError(t *testing.T) {
	reg := newFakeIndexRegistry(t, "arm64")
	st := NewStore(t.TempDir())

	if _, err := Resolve(reg.ref(), "arm64", st, nil); err != nil {
		t.Fatal(err) // populate the cache
	}

	reg.denyStatus = 403
	_, err := Resolve(reg.ref(), "arm64", st, nil)
	if err == nil {
		t.Fatal("403 on the freshness HEAD fell back to the cached image")
	}
	if !strings.Contains(err.Error(), "403 Forbidden") {
		t.Errorf("error hides the refusal status: %v", err)
	}
	if !strings.Contains(err.Error(), "NOT used silently") {
		t.Errorf("error does not explain the refused fallback: %v", err)
	}
	if !strings.Contains(err.Error(), "-image ") || !strings.Contains(err.Error(), "@sha256:") {
		t.Errorf("error does not offer the digest-pinned workaround: %v", err)
	}
}

// A registry that cannot be reached at all (connection refused) keeps the
// documented offline degradation: cached image + warning.
func TestCacheFallbackOnUnreachableRegistry(t *testing.T) {
	reg := newFakeIndexRegistry(t, "arm64")
	st := NewStore(t.TempDir())

	if _, err := Resolve(reg.ref(), "arm64", st, nil); err != nil {
		t.Fatal(err)
	}
	reg.srv.Close() // nothing listening anymore

	var warnings []string
	say := func(format string, a ...any) { warnings = append(warnings, fmt.Sprintf(format, a...)) }
	r, err := Resolve(reg.ref(), "arm64", st, say)
	if err != nil {
		t.Fatalf("unreachable registry with a cached image must degrade, got: %v", err)
	}
	if !r.Cached {
		t.Error("expected an offline cache hit")
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "registry unreachable") {
		t.Errorf("expected exactly one unreachable warning, got %v", warnings)
	}
}

// A 5xx is a transient outage, not a refusal: the cached image is used
// with a warning, same as a network error.
func TestCacheFallbackOn5xx(t *testing.T) {
	reg := newFakeIndexRegistry(t, "arm64")
	st := NewStore(t.TempDir())

	if _, err := Resolve(reg.ref(), "arm64", st, nil); err != nil {
		t.Fatal(err)
	}
	reg.denyStatus = 503

	var warnings []string
	say := func(format string, a ...any) { warnings = append(warnings, fmt.Sprintf(format, a...)) }
	r, err := Resolve(reg.ref(), "arm64", st, say)
	if err != nil {
		t.Fatalf("503 outage with a cached image must degrade, got: %v", err)
	}
	if !r.Cached {
		t.Error("expected an offline cache hit on 503")
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "registry unreachable") {
		t.Errorf("expected one unreachable warning, got %v", warnings)
	}
}
