package image

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ejpir/gantry/internal/atomicfile"
	"github.com/ejpir/gantry/internal/gutil"
)

// store.go — the on-disk image cache (design doc: "Store layout").
//
//	~/.gantry/images/
//	  index.json                ref -> manifest digest, atomic rewrite
//	  <digest>.erofs            the built filesystem
//	  <digest>.json             metadata: config + provenance
//	  <digest>.lock             build lock
//	  tmp/                      in-flight builds, cleaned on start

// Meta is <digest>.json: provenance plus the image config.
type Meta struct {
	Ref       string  `json:"ref"`
	Digest    string  `json:"digest"`              // platform manifest digest — names the content
	RefDigest string  `json:"refDigest,omitempty"` // digest the ref resolved to (index digest for multi-arch)
	Arch      string  `json:"arch"`
	Created   string  `json:"created"`
	Size      int64   `json:"size"`
	Config    *Config `json:"config,omitempty"`
}

// refKey indexes refs per architecture: an arm64 pull of debian:latest
// and an amd64 pull are different images and must not share a slot.
func refKey(ref, arch string) string { return ref + "/" + arch }

// Store is the image cache root.
type Store struct {
	root           string
	writeIndexHook func(map[string]string) error
}

// DefaultStore is ~/.gantry/images (GANTRY_IMAGES overrides, mainly for
// tests and the AWS harness).
func DefaultStore() *Store {
	if d := os.Getenv("GANTRY_IMAGES"); d != "" {
		return &Store{root: d}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		home = "/tmp"
	}
	return &Store{root: filepath.Join(home, ".gantry", "images")}
}

// NewStore is an explicit-root store (tests).
func NewStore(root string) *Store { return &Store{root: root} }

// digestFile sanitizes "sha256:abc..." into a filename-safe prefix.
func digestFile(digest string) string {
	return strings.NewReplacer(":", "-", "/", "-").Replace(digest)
}

// ErofsPath is the cached image path for a digest.
func (s *Store) ErofsPath(digest string) string {
	return filepath.Join(s.root, digestFile(digest)+".erofs")
}

func (s *Store) metaPath(digest string) string {
	return filepath.Join(s.root, digestFile(digest)+".json")
}

func (s *Store) lockPath(digest string) string {
	return filepath.Join(s.root, digestFile(digest)+".lock")
}

// ReadMeta loads the metadata for a cached digest.
func (s *Store) ReadMeta(digest string) (*Meta, error) {
	b, err := os.ReadFile(s.metaPath(digest))
	if err != nil {
		return nil, err
	}
	var m Meta
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// LookupRef resolves ref+arch to a cached digest via index.json.
func (s *Store) LookupRef(ref, arch string) (string, bool) {
	digest, ok := s.readIndex()[refKey(ref, arch)]
	return digest, ok
}

func (s *Store) readIndex() map[string]string {
	b, err := os.ReadFile(filepath.Join(s.root, "index.json"))
	if err != nil {
		return map[string]string{}
	}
	var idx struct {
		Refs map[string]string `json:"refs"`
	}
	if json.Unmarshal(b, &idx) != nil || idx.Refs == nil {
		return map[string]string{}
	}
	return idx.Refs
}

func (s *Store) writeIndex(refs map[string]string) error {
	if s.writeIndexHook != nil {
		return s.writeIndexHook(refs)
	}
	b, err := json.MarshalIndent(struct {
		Refs map[string]string `json:"refs"`
	}{refs}, "", "  ")
	if err != nil {
		return err
	}
	// Ref metadata can name private registries, so it remains mode 0600.
	return atomicfile.WriteFileDurable(filepath.Join(s.root, "index.json"), b, 0o600)
}

// indexTransaction serializes index.json read-modify-write cycles across
// processes. Concurrent builds of DIFFERENT digests take different
// per-digest locks, so without this global index lock their readIndex →
// modify → writeIndex sequences interleave and lose each other's entries
// (review finding 4). Lock ordering note: the per-digest build lock is
// always taken BEFORE the index lock (ensure → indexRef); Remove takes
// only the index lock, so the two can never deadlock.
func (s *Store) indexTransaction(fn func() error) error {
	lock, err := gutil.LockFile(filepath.Join(s.root, "index.lock"))
	if err != nil {
		return fmt.Errorf("index lock: %w", err)
	}
	defer func() { _ = lock.Close() }()
	return fn()
}

// cleanDigestLitter removes leftover temp outputs for one digest. It runs only
// under that digest's build lock, so no live build can own the files it
// deletes.
func (s *Store) cleanDigestLitter(digest string) {
	base := digestFile(digest) + ".erofs"
	ents, err := os.ReadDir(s.root)
	if err != nil {
		return
	}
	for _, e := range ents {
		n := e.Name()
		if strings.HasPrefix(n, base+".") && strings.HasSuffix(n, ".tmp") {
			_ = os.Remove(filepath.Join(s.root, n))
		}
	}
}

// ensure returns the cached image for digest, building it under an
// exclusive lock when absent. build receives the temp output path and
// returns the metadata to record. Concurrent gantry processes serialize
// on the .lock file; readers only ever see the final path.
func (s *Store) ensure(digest string, build func(outPath string) (*Meta, error)) (*Meta, error) {
	if err := os.MkdirAll(s.root, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(s.root, 0o700); err != nil {
		return nil, fmt.Errorf("secure image store: %w", err)
	}
	if m, err := s.ReadMeta(digest); err == nil {
		if gutil.FileExists(s.ErofsPath(digest)) {
			if err := s.indexRef(m, digest); err != nil {
				return nil, err
			}
			return m, nil
		}
	}
	lock, err := gutil.LockFile(s.lockPath(digest))
	if err != nil {
		return nil, fmt.Errorf("another gantry process is building %s", digest[:19])
	}
	defer func() { _ = lock.Close() }()
	// re-check under the lock
	if m, err := s.ReadMeta(digest); err == nil && gutil.FileExists(s.ErofsPath(digest)) {
		if err := s.indexRef(m, digest); err != nil {
			return nil, err
		}
		return m, nil
	}
	// Only this digest's own temp files, and only under its lock.
	s.cleanDigestLitter(digest)
	m, err := build(s.ErofsPath(digest))
	if err != nil {
		return nil, err
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := atomicfile.WriteFileDurable(s.metaPath(digest), b, 0o600); err != nil {
		return nil, err
	}
	if err := s.indexRef(m, digest); err != nil {
		return nil, err
	}
	return m, nil
}

// indexRef records ref+arch -> digest. It runs inside the global index
// transaction lock so concurrent builds of different digests cannot lose
// each other's entries.
func (s *Store) indexRef(m *Meta, digest string) error {
	return s.indexTransaction(func() error {
		refs := s.readIndex()
		if refs[refKey(m.Ref, m.Arch)] == digest {
			return nil
		}
		refs[refKey(m.Ref, m.Arch)] = digest
		return s.writeIndex(refs)
	})
}

// List returns every cached image's metadata.
func (s *Store) List() []*Meta {
	ents, err := os.ReadDir(s.root)
	if err != nil {
		return nil
	}
	var out []*Meta
	for _, e := range ents {
		if !strings.HasSuffix(e.Name(), ".json") || e.Name() == "index.json" {
			continue
		}
		if m, err := s.ReadMeta(strings.TrimSuffix(e.Name(), ".json")); err == nil {
			out = append(out, m)
		}
	}
	return out
}

// Remove drops cached images (by ref or digest) and their index
// entries. A ref removes every arch variant of that ref. The index
// update runs inside the global index transaction lock (concurrent
// builds must not lose it).
func (s *Store) Remove(refOrDigest string) error {
	return s.indexTransaction(func() error {
		digests := map[string]bool{}
		refs := s.readIndex()
		if strings.Contains(refOrDigest, "sha256:") {
			digests[refOrDigest] = true
		} else {
			for k, d := range refs {
				if k == refOrDigest || strings.HasPrefix(k, refOrDigest+"/") {
					digests[d] = true
				}
			}
		}
		if len(digests) == 0 {
			return fmt.Errorf("no cached image for %q", refOrDigest)
		}
		for k, d := range refs {
			if digests[d] {
				delete(refs, k)
			}
		}
		// The index is authoritative: remove its references before deleting
		// content. If persistence fails, every old reference still has all of
		// its files; a successful index update followed by a cleanup failure
		// leaves only harmless unreferenced data.
		if err := s.writeIndex(refs); err != nil {
			return err
		}
		var cleanupErr error
		for d := range digests {
			for _, path := range []string{s.ErofsPath(d), s.metaPath(d), s.lockPath(d)} {
				if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
					cleanupErr = errors.Join(cleanupErr, fmt.Errorf("remove %s: %w", path, err))
				}
			}
		}
		return cleanupErr
	})
}

// nowRFC is a seam for tests.
var nowRFC = func() string { return time.Now().UTC().Format(time.RFC3339) }
