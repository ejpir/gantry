package image

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ejpir/gantry/internal/gutil"
	"github.com/ejpir/gantry/internal/image/auth"
)

// registry.go — the read side of the OCI registry v2 protocol
// (docs/oci-images.md: "Wire protocol"). ~300 lines, no dependency: a
// 401-driven bearer-token dance, per-repo scope tokens cached in memory,
// Authorization stripped on cross-host redirects, sha256 verification on
// every blob.

// registryClient pulls from one registry with one credential resolver.
type registryClient struct {
	reg    string
	cred   *auth.Credential // nil = anonymous
	hc     *http.Client
	logf   func(string, ...any)
	debug  bool // GANTRY_DEBUG_REGISTRY: wire-level GET lines
	mu     sync.Mutex
	tokens map[string]*bearerToken // scope -> token (memory only, never disk)
}

type bearerToken struct {
	value   string
	expires time.Time
}

// imageManifest is the union we care about: a single-platform manifest
// (config+layers) or an OCI index / docker manifest list (manifests).
type imageManifest struct {
	MediaType string       `json:"mediaType"`
	Config    descriptor   `json:"config"`
	Layers    []descriptor `json:"layers"`
	Manifests []struct {
		Digest   string `json:"digest"`
		Platform struct {
			Architecture string `json:"architecture"`
			OS           string `json:"os"`
		} `json:"platform"`
		Size int64 `json:"size"`
	} `json:"manifests"`
}

// media types we accept for manifests (OCI + docker schema 2).
const manifestAccept = "application/vnd.oci.image.manifest.v1+json, " +
	"application/vnd.oci.image.index.v1+json, " +
	"application/vnd.docker.distribution.manifest.v2+json, " +
	"application/vnd.docker.distribution.manifest.list.v2+json"

func newRegistryClient(reg string, cred *auth.Credential, logf func(string, ...any)) *registryClient {
	c := &registryClient{
		reg: reg, cred: cred, logf: logf,
		debug:  gutil.EnvOr("GANTRY_DEBUG_REGISTRY") != "",
		tokens: map[string]*bearerToken{},
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// No keep-alives. A pull is a handful of requests, and an idle
	// persistent connection behind a MITM/filtering proxy invites
	// injected bytes — observed in the field as the proxy's HTML block
	// page arriving late on an idle channel ("unsolicited response
	// received on idle HTTP channel") after it had already answered a
	// request with a refusal.
	transport.DisableKeepAlives = true
	c.hc = &http.Client{
		Transport: transport,
		Timeout:   5 * time.Minute, // blob downloads can be slow
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Strip Authorization when the redirect leaves the origin
			// authority (host AND port): blob GETs redirect to
			// S3/GCS/CDN URLs that carry their own presigned auth, and
			// forwarding our bearer token would hand registry
			// credentials to a third-party service. Go's built-in strip
			// compares hostnames only — same-host different-port still
			// forwards — so this check is ours (and has a test).
			if len(via) > 0 && !strings.EqualFold(req.URL.Host, via[0].URL.Host) {
				req.Header.Del("Authorization")
			}
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}
	return c
}

// scheme is https everywhere except loopback registries (Docker's own
// insecure exception; also what httptest runs on).
func (c *registryClient) scheme() string {
	if isLoopbackRegistry(c.reg) {
		return "http"
	}
	return "https"
}

func (c *registryClient) log(format string, a ...any) {
	if c.logf != nil && c.debug {
		c.logf("registry: "+format, a...)
	}
}

// do issues one request, running the 401 → token → retry dance on the
// first unauthenticated failure. Credentials are only ever attached to
// requests addressed at our own registry (or the token realm it names).
func (c *registryClient) do(ctx context.Context, method, rawurl, accept, scope string) (*http.Response, error) {
	send := func(withToken bool) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, method, rawurl, nil)
		if err != nil {
			return nil, err
		}
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		// attach a cached token up front (saves a 401 round-trip per
		// request); withToken=false forces the unauthenticated probe
		// that discovers the challenge in the first place.
		if withToken && scope != "" {
			if tok := c.tokenFor(ctx, scope); tok != "" {
				req.Header.Set("Authorization", "Bearer "+tok)
			}
		}
		c.log("%s %s", method, rawurl) // method+URL+status only, NEVER headers
		return c.hc.Do(req)
	}
	resp, err := send(true) // cached token if we have one, else anonymous
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusUnauthorized || scope == "" {
		return resp, nil
	}
	chal := resp.Header.Get("WWW-Authenticate")
	resp.Body.Close()
	// Registries answering Basic get Basic directly — HTTPS only, never
	// over plaintext (loopback excepted, per isLoopbackRegistry).
	if strings.HasPrefix(chal, "Basic") {
		if c.cred == nil || c.cred.Username == "" {
			return nil, fmt.Errorf("%s requires basic auth but no credential is configured", c.reg)
		}
		if c.scheme() != "https" && !isLoopbackRegistry(c.reg) {
			return nil, fmt.Errorf("refusing to send basic-auth credentials to %s over plaintext HTTP", c.reg)
		}
		req, err := http.NewRequestWithContext(ctx, method, rawurl, nil)
		if err != nil {
			return nil, err
		}
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		req.SetBasicAuth(c.cred.Username, c.cred.Secret.Raw())
		return c.hc.Do(req)
	}
	// parse WWW-Authenticate and retry with a token
	if err := c.acquireToken(ctx, chal, scope); err != nil {
		return nil, err
	}
	return send(true)
}

// acquireToken implements step 3 of the dance: GET <realm>?service&scope
// with HTTP Basic when we have a username/password, no auth header for
// anonymous (Docker Hub REQUIRES the anonymous token request — skipping
// it makes public pulls fail in a way that looks like a credential
// problem), or the refresh-token grant for identity tokens.
func (c *registryClient) acquireToken(ctx context.Context, challenge, wantScope string) error {
	if !strings.HasPrefix(challenge, "Bearer ") {
		if strings.HasPrefix(challenge, "Basic") && c.cred != nil {
			return nil // caller retries with Basic directly (https only, see do)
		}
		return fmt.Errorf("unsupported auth challenge %q from %s", challenge, c.reg)
	}
	params := map[string]string{}
	for _, kv := range strings.Split(strings.TrimPrefix(challenge, "Bearer "), ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(kv), "=")
		if ok {
			params[k] = strings.Trim(v, `"`)
		}
	}
	realm := params["realm"]
	if realm == "" {
		return fmt.Errorf("bearer challenge without realm from %s", c.reg)
	}
	scope := params["scope"]
	if wantScope != "" {
		scope = wantScope
	}

	u, err := url.Parse(realm)
	if err != nil {
		return err
	}
	q := u.Query()
	if params["service"] != "" {
		q.Set("service", params["service"])
	}
	if scope != "" {
		q.Set("scope", scope)
	}
	u.RawQuery = q.Encode()

	var req *http.Request
	if c.cred != nil && c.cred.IdentityToken {
		// identity token: POST the refresh-token grant
		form := url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {c.cred.Secret.Raw()},
		}
		if scope != "" {
			form.Set("scope", scope)
		}
		if params["service"] != "" {
			form.Set("service", params["service"])
		}
		req, err = http.NewRequestWithContext(ctx, "POST", realm, strings.NewReader(form.Encode()))
		if err == nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	} else {
		req, err = http.NewRequestWithContext(ctx, "GET", u.String(), nil)
		if err == nil && c.cred != nil && c.cred.Username != "" {
			req.SetBasicAuth(c.cred.Username, c.cred.Secret.Raw())
		}
	}
	if err != nil {
		return err
	}
	c.log("token request %s (scope %s)", realm, scope)
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("token request failed: %s", resp.Status)
	}
	var tok struct {
		Token     string `json:"token"`
		AccessTok string `json:"access_token"`
		ExpiresIn int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return err
	}
	value := tok.Token
	if value == "" {
		value = tok.AccessTok
	}
	if value == "" {
		return fmt.Errorf("token endpoint returned no token")
	}
	exp := time.Now().Add(5 * time.Minute)
	if tok.ExpiresIn > 0 {
		exp = time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second)
	}
	c.mu.Lock()
	c.tokens[scope] = &bearerToken{value: value, expires: exp}
	c.mu.Unlock()
	return nil
}

// tokenFor returns a cached, unexpired token for the scope.
func (c *registryClient) tokenFor(ctx context.Context, scope string) string {
	c.mu.Lock()
	t := c.tokens[scope]
	c.mu.Unlock()
	if t != nil && time.Now().Before(t.expires.Add(-30*time.Second)) {
		return t.value
	}
	return ""
}

// fetchManifest GETs a manifest (or index) by tag or digest.
func (c *registryClient) fetchManifest(ctx context.Context, repo, reference string) ([]byte, string, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	u := fmt.Sprintf("%s://%s/v2/%s/manifests/%s", c.scheme(), c.reg, repo, reference)
	resp, err := c.do(ctx, "GET", u, manifestAccept, "repository:"+repo+":pull")
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("manifest %s@%s: %s", repo, reference, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, "", err
	}
	// never trust the header over the content: the digest under which we
	// cache (and later serve digest-pinned pulls) is the body's hash; a
	// header that disagrees means a broken or hostile registry
	digest := fmt.Sprintf("sha256:%x", sha256.Sum256(b))
	if hdr := resp.Header.Get("Docker-Content-Digest"); hdr != "" && hdr != digest {
		return nil, "", fmt.Errorf("manifest %s@%s: Docker-Content-Digest %s does not match content %s", repo, reference, hdr, digest)
	}
	return b, digest, nil
}

// statusError is a definitive HTTP answer to a registry request: the
// registry (or a middlebox) ANSWERED, so callers must not blindly file
// it under "registry unreachable" — a 403 from a filtering proxy is a
// policy refusal, not a network outage. Callers decide by code class:
// 4xx is a refusal (won't heal by itself), 5xx is a transient outage.
type statusError struct {
	op        string
	repo      string
	reference string
	status    string
	code      int
}

func (e *statusError) Error() string {
	return fmt.Sprintf("%s manifest %s@%s: %s", e.op, e.repo, e.reference, e.status)
}

// headManifest returns the registry's current digest for a reference
// without downloading the manifest (Docker-Content-Digest on a HEAD).
func (c *registryClient) headManifest(ctx context.Context, repo, reference string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	u := fmt.Sprintf("%s://%s/v2/%s/manifests/%s", c.scheme(), c.reg, repo, reference)
	resp, err := c.do(ctx, "HEAD", u, manifestAccept, "repository:"+repo+":pull")
	if err != nil {
		return "", err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", &statusError{op: "HEAD", repo: repo, reference: reference, status: resp.Status, code: resp.StatusCode}
	}
	return resp.Header.Get("Docker-Content-Digest"), nil
}

// fetchBlob streams a blob to dst, verifying its sha256.
func (c *registryClient) fetchBlob(ctx context.Context, repo string, desc descriptor, dst string) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute) // huge layers, slow links
	defer cancel()
	u := fmt.Sprintf("%s://%s/v2/%s/blobs/%s", c.scheme(), c.reg, repo, desc.Digest)
	resp, err := c.do(ctx, "GET", u, "", "repository:"+repo+":pull")
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("blob %s: %s", desc.Digest, resp.Status)
	}
	f, err := os.Create(dst)
	if err != nil {
		return 0, err
	}
	h := sha256.New()
	// cap by the descriptor size (+1 to detect overflow): a broken or
	// hostile registry must not fill the disk before the digest check
	n, err := io.Copy(f, io.TeeReader(io.LimitReader(resp.Body, desc.Size+1), h))
	if err == nil && n > desc.Size {
		err = fmt.Errorf("blob %s: larger than its descriptor (%d > %d bytes)", desc.Digest, n, desc.Size)
	}
	cerr := f.Close()
	if err != nil {
		os.Remove(dst)
		return 0, err
	}
	if cerr != nil {
		return 0, cerr
	}
	if got := fmt.Sprintf("sha256:%x", h.Sum(nil)); got != desc.Digest {
		os.Remove(dst)
		return 0, fmt.Errorf("blob %s: digest mismatch (got %s, size %d)", desc.Digest, got, n)
	}
	return n, nil
}

// ---------------- pulled source ----------------

// loadRegistry pulls ref from its registry: manifest (platform-matched
// through an index when needed), config, and layers decompressed to temp
// files. Every digest on the way is verified.
func loadRegistry(ctx context.Context, refStr, arch string, res *auth.Resolver, logf func(string, ...any)) (*pulled, error) {
	ref, err := ParseRef(refStr)
	if err != nil {
		return nil, err
	}
	c := newRegistryClient(ref.Registry, res.For(ref.Registry), logf)

	reference := ref.Tag
	if ref.Digest != "" {
		reference = ref.Digest
	}
	manb, manDigest, err := c.fetchManifest(ctx, ref.Repo, reference)
	if err != nil {
		return nil, err
	}
	if ref.Digest != "" && manDigest != ref.Digest {
		return nil, fmt.Errorf("digest-pinned pull: registry returned %s for %s", manDigest, ref.Digest)
	}

	// refDigest records what the REF resolved to — for a multi-arch
	// image this is the INDEX digest, which is what a later HEAD of the
	// tag returns; the cache lookup compares like with like
	refDigest := manDigest
	var head imageManifest
	if err := json.Unmarshal(manb, &head); err != nil {
		return nil, fmt.Errorf("bad manifest: %w", err)
	}

	// index/manifest-list: descend to the platform manifest
	if len(head.Manifests) > 0 {
		want := archToOCI(arch)
		var pick string
		for _, m := range head.Manifests {
			if m.Platform.Architecture == want && (m.Platform.OS == "" || m.Platform.OS == "linux") {
				pick = m.Digest
				break
			}
		}
		if pick == "" {
			return nil, fmt.Errorf("image %s has no manifest for linux/%s", refStr, want)
		}
		manb, manDigest, err = c.fetchManifest(ctx, ref.Repo, pick)
		if err != nil {
			return nil, err
		}
		if manDigest != pick {
			return nil, fmt.Errorf("platform manifest digest mismatch")
		}
		head = imageManifest{}
		if err := json.Unmarshal(manb, &head); err != nil {
			return nil, fmt.Errorf("bad platform manifest: %w", err)
		}
	}

	tmp, err := os.MkdirTemp("", "gantry-image-")
	if err != nil {
		return nil, err
	}
	p := &pulled{digest: manDigest, refDigest: refDigest, ref: refStr, tmpDir: tmp}
	fail := func(err error) (*pulled, error) { p.Close(); return nil, err }

	cfgPath := filepath.Join(tmp, "config.json")
	if _, err := c.fetchBlob(ctx, ref.Repo, head.Config, cfgPath); err != nil {
		return fail(fmt.Errorf("config blob: %w", err))
	}
	cfgb, err := os.ReadFile(cfgPath)
	if err != nil {
		return fail(err)
	}
	var oc ociConfig
	if err := json.Unmarshal(cfgb, &oc); err != nil {
		return fail(fmt.Errorf("bad image config: %w", err))
	}
	if err := checkPlatform(&oc, arch, refStr); err != nil {
		return fail(err)
	}

	if logf != nil && len(head.Layers) > 0 {
		var total int64
		for _, l := range head.Layers {
			total += l.Size
		}
		logf("pulling %s (%d layers, %s)", ref.String(), len(head.Layers), gutil.HumanSize(total))
	}
	for i, l := range head.Layers {
		if logf != nil {
			logf("layer %d/%d: %s (%s)", i+1, len(head.Layers), gutil.HumanSize(l.Size), l.Digest[:19])
		}
		blobPath := filepath.Join(tmp, strconv.Itoa(i)+".blob")
		if _, err := c.fetchBlob(ctx, ref.Repo, l, blobPath); err != nil {
			return fail(err)
		}
		f, err := decompressTo(blobPath, l.Digest, tmp, i)
		if err != nil {
			return fail(err)
		}
		os.Remove(blobPath)
		p.layers = append(p.layers, f)
	}
	p.config = &Config{
		Env:        oc.Config.Env,
		Entrypoint: oc.Config.Entrypoint,
		Cmd:        oc.Config.Cmd,
		User:       oc.Config.User,
		WorkingDir: oc.Config.WorkingDir,
	}
	return p, nil
}
