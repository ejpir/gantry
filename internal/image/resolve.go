package image

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gantry/internal/gutil"
	"gantry/internal/image/auth"
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

// cachedRef resolves a reference from the cache without a pull when
// possible: a digest-pinned ref is a pure cache lookup; a tagged ref
// costs one HEAD (the doc's "re-pull of an unchanged tag is a no-op"),
// and an unreachable registry with a cached image degrades to an
// offline cache hit with a warning rather than a failure.
func cachedRef(ref, arch string, st *Store, res *auth.Resolver, say func(string, ...any)) (*Resolved, bool) {
	parsed, err := ParseRef(ref)
	if err != nil {
		return nil, false
	}
	hit := func(digest string) (*Resolved, bool) {
		m, err := st.ReadMeta(digest)
		if err != nil || !gutil.FileExists(st.ErofsPath(digest)) {
			return nil, false
		}
		return &Resolved{Digest: digest, Path: st.ErofsPath(digest), Config: m.Config, Ref: ref, Cached: true}, true
	}
	if parsed.Digest != "" {
		return hit(parsed.Digest)
	}
	cached, ok := st.LookupRef(ref)
	if !ok {
		return nil, false
	}
	c := newRegistryClient(parsed.Registry, res.For(parsed.Registry), nil)
	current, err := c.headManifest(context.Background(), parsed.Repo, parsed.Tag)
	if err != nil {
		say("registry unreachable (%v); using cached %s", err, cached[:19])
		return hit(cached)
	}
	if current == cached {
		return hit(cached)
	}
	return nil, false // tag moved: full pull
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
	return ResolveAuth(ref, arch, st, nil, logf)
}

// ResolveAuth is Resolve with an explicit credential resolver (nil
// resolves from the environment, which is what the CLI wants).
func ResolveAuth(ref, arch string, st *Store, res *auth.Resolver, logf func(string, ...any)) (*Resolved, error) {
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
	} else {
		// 4. image reference → registry pull (cached by manifest digest)
		if res == nil {
			res = auth.Resolve()
		}
		if r, ok := cachedRef(ref, arch, st, res, say); ok {
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
	if m, err := st.ensure(p.digest, func(outPath string) (*Meta, error) {
		say("building %s → %s (linux/%s)", ref, p.digest[:19], arch)
		if _, err := Build(outPath, p.layers, p.config, logf); err != nil {
			return nil, err
		}
		fi, _ := os.Stat(outPath)
		var size int64
		if fi != nil {
			size = fi.Size()
		}
		return &Meta{
			Ref: ref, Digest: p.digest, Arch: arch,
			Created: nowRFC(), Size: size, Config: p.config,
		}, nil
	}); err != nil {
		return nil, err
	} else {
		return &Resolved{
			Digest: p.digest,
			Path:   st.ErofsPath(p.digest),
			Config: m.Config,
			Ref:    ref,
			Cached: true,
		}, nil
	}
}
