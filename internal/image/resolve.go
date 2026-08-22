package image

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ejpir/gantry/internal/gutil"
	"github.com/ejpir/gantry/internal/image/auth"
)

// resolve.go — turn an -image value into a usable rootfs disk plus the
// image config. Disambiguation per docs/oci-images.md:
//
//  1. existing file ending in .erofs → use as-is (no config available)
//  2. directory containing oci-layout → OCI layout source
//  3. existing file that parses as a docker save tar → docker save source
//  4. otherwise → image reference; registry pull (Phase 2)
//
// Resolved images are cached by manifest digest in the Store.

// Resolved is an image ready to attach as /dev/vdb.
type Resolved struct {
	Digest string  // manifest digest (cache key); "" for direct .erofs files
	Path   string  // the .erofs to attach
	Config *Config // nil for direct .erofs files (no config available)
	Ref    string
	Cached bool // false when built during this call
}

// localCachedRef resolves a reference entirely from the verified local cache.
// It performs no credential lookup and no network request. Tagged references
// use the last digest explicitly recorded for that ref and architecture;
// digest-pinned references may also directly name a cached manifest.
func localCachedRef(ref, arch string, st *Store) *Resolved {
	parsed, err := ParseRef(ref)
	if err != nil {
		return nil
	}
	hit := func(digest string) *Resolved {
		m, err := st.ReadMeta(digest)
		if err != nil || m.Arch != arch || !gutil.FileExists(st.ErofsPath(digest)) {
			return nil
		}
		return &Resolved{Digest: digest, Path: st.ErofsPath(digest), Config: m.Config, Ref: ref, Cached: true}
	}
	if parsed.Digest != "" {
		// A pinned digest may name either the platform manifest or its index.
		if digest, ok := st.LookupRef(ref, arch); ok {
			if m, err := st.ReadMeta(digest); err == nil {
				refDigest := m.RefDigest
				if refDigest == "" {
					refDigest = m.Digest
				}
				if digest == parsed.Digest || refDigest == parsed.Digest {
					return hit(digest)
				}
			}
		}
		return hit(parsed.Digest)
	}
	digest, ok := st.LookupRef(ref, arch)
	if !ok {
		return nil
	}
	return hit(digest)
}

// cachedRef resolves a reference from the cache without a pull when
// possible: a digest-pinned ref is a pure cache lookup; a tagged ref
// costs one HEAD (the doc's "re-pull of an unchanged tag is a no-op").
// An UNREACHABLE registry (network error: DNS/TCP/TLS/timeout, or a
// transient 5xx) with a cached image degrades to an offline cache hit
// with a warning rather than a failure. A registry that ANSWERS with a
// 4xx (a 403 from a filtering proxy, a 401 after the token dance) is a
// refusal, not an outage: silently booting a stale cache would hide an
// auth/policy problem, so it is a hard error instead. A nil *Resolved
// with a nil error means "not in cache — do a full pull".
func cachedRef(ref, arch string, st *Store, res *auth.Resolver, say func(string, ...any)) (*Resolved, error) {
	parsed, err := ParseRef(ref)
	if err != nil {
		return nil, nil
	}
	hit := func(digest string) *Resolved {
		m, err := st.ReadMeta(digest)
		if err != nil || !gutil.FileExists(st.ErofsPath(digest)) {
			return nil
		}
		if m.Arch != arch {
			return nil // a cached image for the wrong arch must not boot
		}
		return &Resolved{Digest: digest, Path: st.ErofsPath(digest), Config: m.Config, Ref: ref, Cached: true}
	}
	// refDigest is what lookups compare against: the index digest for a
	// multi-arch pull and the manifest digest for a single-arch pull.
	refDigest := func(m *Meta) string {
		if m.RefDigest != "" {
			return m.RefDigest
		}
		return m.Digest
	}
	if parsed.Digest != "" {
		// a pinned digest may name the platform manifest OR the index
		if d, ok := st.LookupRef(ref, arch); ok {
			if m, err := st.ReadMeta(d); err == nil && (d == parsed.Digest || refDigest(m) == parsed.Digest) {
				return hit(d), nil
			}
		}
		return hit(parsed.Digest), nil
	}
	cached, ok := st.LookupRef(ref, arch)
	if !ok {
		return nil, nil
	}
	m, err := st.ReadMeta(cached)
	if err != nil || m.Arch != arch {
		return nil, nil
	}
	c := newRegistryClient(parsed.Registry, res.For(parsed.Registry), nil)
	current, err := c.headManifest(context.Background(), parsed.Repo, parsed.Tag)
	if err != nil {
		var se *statusError
		if errors.As(err, &se) && se.code >= 400 && se.code < 500 {
			pinned := parsed.Registry + "/" + parsed.Repo + "@" + cached
			return nil, fmt.Errorf(`%v
The registry (or a filtering proxy) actively REFUSED the freshness
check — this is an auth/policy refusal, not an outage, so the cached
image is NOT used silently. Restore registry access, or pin the
cached digest:

    -image %s`, err, pinned)
		}
		say("registry unreachable (%v); using cached %s", err, shortDigest(cached))
		return hit(cached), nil
	}
	if current == refDigest(m) {
		return hit(cached), nil
	}
	return nil, nil // tag moved: full pull
}

// looksLikeMissingPath reports whether ref is shaped like an explicit
// local path (path-prefix or an archive suffix) — in which case a
// missing file is a clear "not found" error, never a registry pull.
func looksLikeMissingPath(ref string) bool {
	if strings.HasPrefix(ref, ".") || strings.HasPrefix(ref, "/") || strings.HasPrefix(ref, "~") {
		return true
	}
	for _, suf := range []string{".tar", ".tgz", ".tar.gz", ".oci", ".erofs"} {
		if strings.HasSuffix(ref, suf) {
			return true
		}
	}
	return false
}

// LooksLikeRef reports whether value should be parsed as an image
// reference rather than a path: no path separator start, no .erofs
// suffix, and it matches the familiar name[:tag] / name@digest shapes.
func LooksLikeRef(v string) bool {
	if strings.HasSuffix(v, ".erofs") || strings.HasPrefix(v, ".") ||
		strings.HasPrefix(v, "/") || strings.HasPrefix(v, "~") {
		return false
	}
	if _, err := os.Stat(v); err == nil {
		return false // an existing path always wins
	}
	// has a registry host, a library/ name, or a bare name with tag/digest
	return true
}

// Resolve makes ref usable and returns the cached (or freshly built)
// rootfs. arch is the GUEST kernel arch (from vmm.KernelArch), not the
// host's. logf may be nil.
func Resolve(ref, arch string, st *Store, logf func(string, ...any)) (*Resolved, error) {
	return resolveAuth(ref, arch, st, nil, logf, false, false)
}

// ResolvePreferCached is Resolve for latency-sensitive execution. Existing
// tagged references use their verified local cache entry without invoking a
// credential helper or registry. Cache misses still pull normally. Call
// Resolve (as `gantry image pull` does) when remote tag freshness is required.
func ResolvePreferCached(ref, arch string, st *Store, logf func(string, ...any)) (*Resolved, error) {
	return resolveAuth(ref, arch, st, nil, logf, true, false)
}

// ResolveCachedOnly never consults registry credentials or the network.
// Existing local sources may still be imported, while an uncached reference
// fails with an explicit `gantry image pull` instruction. Long-lived manager
// processes use this policy so they never become credential holders.
func ResolveCachedOnly(ref, arch string, st *Store, logf func(string, ...any)) (*Resolved, error) {
	return resolveAuth(ref, arch, st, nil, logf, true, true)
}

// ResolveAuth is Resolve with an explicit credential resolver (nil
// resolves from the environment, which is what the CLI wants).
func ResolveAuth(ref, arch string, st *Store, res *auth.Resolver, logf func(string, ...any)) (*Resolved, error) {
	return resolveAuth(ref, arch, st, res, logf, false, false)
}

func resolveAuth(ref, arch string, st *Store, res *auth.Resolver, logf func(string, ...any), preferCached, cachedOnly bool) (*Resolved, error) {
	if st == nil {
		st = DefaultStore()
	}
	say := func(format string, a ...any) {
		if logf != nil {
			logf(format, a...)
		}
	}

	// 1. direct .erofs file
	if st_, err := os.Stat(ref); err == nil && !st_.IsDir() && strings.HasSuffix(ref, ".erofs") {
		return &Resolved{Path: ref, Ref: ref, Cached: true}, nil
	}

	// 2./3. local sources
	var load func() (*pulled, error)
	if st_, err := os.Stat(ref); err == nil && st_.IsDir() {
		if !gutil.FileExists(filepath.Join(ref, "oci-layout")) {
			return nil, fmt.Errorf("%s is a directory but has no oci-layout marker", ref)
		}
		load = func() (*pulled, error) { return loadOCILayout(ref, ref, arch) }
	} else if gutil.FileExists(ref) {
		load = func() (*pulled, error) { return loadDockerSave(ref, ref, arch) }
	} else if looksLikeMissingPath(ref) {
		// An explicit path that doesn't exist must not fall through to
		// the registry branch: ParseRef would mangle "./pi-agent.tar"
		// into a pull from a registry literally named ".".
		return nil, fmt.Errorf("image file not found: %s\n(pass an OCI reference like debian:bookworm-slim, or build the file first — e.g. ./scripts/mkpiimage.sh)", ref)
	} else {
		// 4. image reference → local cache or registry pull. Ordinary VM
		// starts prefer the verified local cache: on macOS, credential-helper
		// and freshness HEAD latency otherwise dominates the entire VM boot.
		if preferCached {
			if cached := localCachedRef(ref, arch, st); cached != nil {
				return cached, nil
			}
		}
		if cachedOnly {
			return nil, fmt.Errorf("image %s is not in the local linux/%s cache; run `gantry image pull %s` before asking the manager to create a sandbox", ref, arch, ref)
		}
		if res == nil {
			res = auth.Resolve()
		}
		for _, err := range res.ParseErrors() {
			say("warning: skipping unparseable credentials file: %v", err)
		}
		r, err := cachedRef(ref, arch, st, res, say)
		if err != nil {
			return nil, err
		}
		if r != nil {
			return r, nil
		}
		load = func() (*pulled, error) { return loadRegistry(context.Background(), ref, arch, res, logf) }
	}

	p, err := load()
	if err != nil {
		return nil, err
	}
	defer p.Close()

	// fast path: exact digest already cached (index lookup is for refs;
	// the digest check covers re-pulls of the same content under any ref)
	built := false
	m, err := st.ensure(p.digest, func(outPath string) (*Meta, error) {
		built = true
		say("building %s → %s (linux/%s)", ref, shortDigest(p.digest), arch)
		if _, err := Build(outPath, p.layers, p.config, logf); err != nil {
			return nil, err
		}
		fi, _ := os.Stat(outPath)
		var size int64
		if fi != nil {
			size = fi.Size()
		}
		return &Meta{
			Ref: ref, Digest: p.digest, RefDigest: p.refDigest, Arch: arch,
			Created: nowRFC(), Size: size, Config: p.config,
		}, nil
	})
	if err != nil {
		return nil, err
	}
	return &Resolved{
		Digest: p.digest,
		Path:   st.ErofsPath(p.digest),
		Config: m.Config,
		Ref:    ref,
		Cached: !built,
	}, nil
}
