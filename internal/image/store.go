package image

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gantry/internal/gutil"
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
	root string
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

// LookupRef resolves ref+arch to a cached digest via index.json. The
// arch-keyed slot wins; a legacy bare-ref slot is returned too (the
// caller still verifies Meta.Arch).
func (s *Store) LookupRef(ref, arch string) (string, bool) {
	idx := s.readIndex()
	if d, ok := idx[refKey(ref, arch)]; ok {
		return d, true
	}
	d, ok := idx[ref]
	return d, ok
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
	b, err := json.MarshalIndent(struct {
		Refs map[string]string `json:"refs"`
	}{refs}, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(s.root, "index.json.tmp")
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(s.root, "index.json"))
}

// cleanCrashLitter removes <digest>.erofs.tmp files: Build writes the
// temp output next to the final path and renames, so a crash mid-build
// leaves the temp behind. Called from ensure; failures are ignored.
func (s *Store) cleanCrashLitter() {
	ents, err := os.ReadDir(s.root)
	if err != nil {
		return
	}
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".erofs.tmp") {
			os.Remove(filepath.Join(s.root, e.Name()))
		}
	}
}

// ensure returns the cached image for digest, building it under an
// exclusive lock when absent. build receives the temp output path and
// returns the metadata to record. Concurrent gantry processes serialize
// on the .lock file; readers only ever see the final path.
func (s *Store) ensure(digest string, build func(outPath string) (*Meta, error)) (*Meta, error) {
	if err := os.MkdirAll(s.root, 0o755); err != nil {
		return nil, err
	}
	if m, err := s.ReadMeta(digest); err == nil {
		if gutil.FileExists(s.ErofsPath(digest)) {
			s.indexRef(m, digest) // migrate legacy arch-less entries
			return m, nil         // cached
		}
	}
	s.cleanCrashLitter()
	lock, err := gutil.LockFile(s.lockPath(digest))
	if err != nil {
		return nil, fmt.Errorf("another gantry process is building %s", digest[:19])
	}
	defer lock.Close()
	// re-check under the lock
	if m, err := s.ReadMeta(digest); err == nil && gutil.FileExists(s.ErofsPath(digest)) {
		return m, nil
	}
	m, err := build(s.ErofsPath(digest))
	if err != nil {
		return nil, err
	}
	b, _ := json.MarshalIndent(m, "", "  ")
	if err := os.WriteFile(s.metaPath(digest), b, 0o644); err != nil {
		return nil, err
	}
	if err := s.indexRef(m, digest); err != nil {
		return nil, err
	}
	return m, nil
}

// indexRef records ref+arch -> digest, dropping the legacy arch-less
// slot for the same ref.
func (s *Store) indexRef(m *Meta, digest string) error {
	refs := s.readIndex()
	if refs[refKey(m.Ref, m.Arch)] == digest {
		return nil
	}
	delete(refs, m.Ref)
	refs[refKey(m.Ref, m.Arch)] = digest
	return s.writeIndex(refs)
}

// SetRefDigest backfills Meta.RefDigest for an image pulled before the
// field existed: without it a multi-arch tag's HEAD compare can never
// match and every pull re-fetches manifests.
func (s *Store) SetRefDigest(digest, refDigest string) {
	m, err := s.ReadMeta(digest)
	if err != nil || m.RefDigest != "" {
		return
	}
	m.RefDigest = refDigest
	if b, err := json.MarshalIndent(m, "", "  "); err == nil {
		os.WriteFile(s.metaPath(digest), b, 0o644)
	}
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
// entries. A ref removes every arch variant of that ref.
func (s *Store) Remove(refOrDigest string) error {
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
	for d := range digests {
		os.Remove(s.ErofsPath(d))
		os.Remove(s.metaPath(d))
		os.Remove(s.lockPath(d))
	}
	for k, d := range refs {
		if digests[d] {
			delete(refs, k)
		}
	}
	return s.writeIndex(refs)
}

// nowRFC is a seam for tests.
var nowRFC = func() string { return time.Now().UTC().Format(time.RFC3339) }
