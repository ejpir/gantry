package shares

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/ejpir/gantry/internal/atomicfile"
)

// Spec is one TAG=PATH[,mount=CTRPATH][,ro][,uid=N,gid=N] host-directory export.
//
// Read-only semantics are enforced on the host by the virtio-fs backend.
// UID/GID optionally replace host numeric ownership in guest-visible
// attributes; host ownership is never changed.
type Spec struct {
	Tag     string
	Path    string
	RO      bool
	UID     *uint32
	GID     *uint32
	CtrPath string
}

// ParseSpec parses one TAG=PATH[,mount=CTRPATH][,ro][,uid=N,gid=N] value. The
// optional mount target must be an absolute container path. Splitting only on
// the first '=' leaves Windows drive colons and additional '=' characters in
// PATH intact.
//
// Collection-level rules such as unique tags belong to ParseSpecs. Keeping
// this function independent of caller-owned state makes single-value parsing
// deterministic and safe to reuse.
func ParseSpec(spec string) (Spec, error) {
	tag, path, ok := strings.Cut(spec, "=")
	if !ok {
		return Spec{}, fmt.Errorf("want TAG=PATH[,mount=CTRPATH][,ro][,uid=N,gid=N]")
	}
	var ro bool
	var uid, gid *uint32
	var mountPath string
	var hasMount, encoded bool
	// Options are suffixes so commas remain valid in the host/container path
	// unless every trailing component is a recognized option.

options:
	for {
		i := strings.LastIndex(path, ",")
		if i < 0 {
			break
		}
		base, opt := path[:i], path[i+1:]
		switch {
		case opt == "ro":
			if ro {
				return Spec{}, fmt.Errorf("duplicate share option ro")
			}
			ro = true
		case opt == "encoding=base64url":
			if encoded {
				return Spec{}, fmt.Errorf("duplicate share option encoding")
			}
			encoded = true
		case strings.HasPrefix(opt, "mount="):
			if hasMount {
				return Spec{}, fmt.Errorf("duplicate share option mount")
			}
			mountPath = strings.TrimPrefix(opt, "mount=")
			if mountPath == "" {
				return Spec{}, fmt.Errorf("empty share mount target")
			}
			hasMount = true
		case strings.HasPrefix(opt, "uid="):
			if uid != nil {
				return Spec{}, fmt.Errorf("duplicate share option uid")
			}
			v, err := strconv.ParseUint(strings.TrimPrefix(opt, "uid="), 10, 32)
			if err != nil {
				return Spec{}, fmt.Errorf("invalid share uid %q: %w", strings.TrimPrefix(opt, "uid="), err)
			}
			n := uint32(v)
			uid = &n
		case strings.HasPrefix(opt, "gid="):
			if gid != nil {
				return Spec{}, fmt.Errorf("duplicate share option gid")
			}
			v, err := strconv.ParseUint(strings.TrimPrefix(opt, "gid="), 10, 32)
			if err != nil {
				return Spec{}, fmt.Errorf("invalid share gid %q: %w", strings.TrimPrefix(opt, "gid="), err)
			}
			n := uint32(v)
			gid = &n
		default:
			// A trailing segment that looks like an option but is not recognized
			// is a typo, not part of the path. Plain commas remain valid in paths.
			if key, _, isOption := strings.Cut(opt, "="); isOption {
				return Spec{}, fmt.Errorf("unknown share option %q (want mount=PATH, ro, uid=N, gid=N)", key)
			}
			break options
		}
		path = base
	}
	if (uid == nil) != (gid == nil) {
		return Spec{}, fmt.Errorf("share ownership mapping requires both uid=N and gid=N")
	}
	if !encoded && !hasMount && strings.Contains(path, "@/") {
		return Spec{}, fmt.Errorf("ambiguous legacy @ mount syntax; use mount=PATH or base64url encoding")
	}
	if encoded {
		decoded, err := base64.RawURLEncoding.DecodeString(path)
		if err != nil {
			return Spec{}, fmt.Errorf("decode share path: %w", err)
		}
		path = string(decoded)
		if hasMount {
			decoded, err = base64.RawURLEncoding.DecodeString(mountPath)
			if err != nil {
				return Spec{}, fmt.Errorf("decode container path: %w", err)
			}
			mountPath = string(decoded)
		}
	}
	if hasMount && !strings.HasPrefix(mountPath, "/") {
		return Spec{}, fmt.Errorf("container mount path must be absolute (got %q)", mountPath)
	}
	if err := ValidateShareTag(tag); err != nil {
		return Spec{}, err
	}
	if path == "" {
		return Spec{}, fmt.Errorf("empty path")
	}
	return Spec{Tag: tag, Path: path, RO: ro, UID: uid, GID: gid, CtrPath: mountPath}, nil
}

// ParseSpecs parses a collection and rejects duplicate tags.
func ParseSpecs(values []string) ([]Spec, error) {
	parsed := make([]Spec, 0, len(values))
	seen := make(map[string]string, len(values))
	for _, value := range values {
		spec, err := ParseSpec(value)
		if err != nil {
			return nil, fmt.Errorf("share %q: %w", value, err)
		}
		if previous, exists := seen[spec.Tag]; exists {
			return nil, fmt.Errorf("duplicate tag %q in %q and %q", spec.Tag, previous, value)
		}
		seen[spec.Tag] = value
		parsed = append(parsed, spec)
	}
	return parsed, nil
}

// String returns the canonical command-line representation of s. It keeps the
// established human-readable form when that form round-trips. If a path
// contains a grammar delimiter, String uses an explicit base64url encoding
// option that was rejected by older parsers, so existing CLI inputs never
// change meaning.
func (s Spec) String() string {
	plain := s.format(false)
	if parsed, err := ParseSpec(plain); err == nil && equalSpec(parsed, s) {
		return plain
	}
	return s.format(true)
}

func (s Spec) format(encoded bool) string {
	hostPath, ctrPath := s.Path, s.CtrPath
	if encoded {
		hostPath = base64.RawURLEncoding.EncodeToString([]byte(hostPath))
		if ctrPath != "" {
			ctrPath = base64.RawURLEncoding.EncodeToString([]byte(ctrPath))
		}
	}

	var b strings.Builder
	b.WriteString(s.Tag)
	b.WriteByte('=')
	b.WriteString(hostPath)
	if ctrPath != "" {
		b.WriteString(",mount=")
		b.WriteString(ctrPath)
	}
	if s.RO {
		b.WriteString(",ro")
	}
	if s.UID != nil && s.GID != nil {
		b.WriteString(",uid=")
		b.WriteString(strconv.FormatUint(uint64(*s.UID), 10))
		b.WriteString(",gid=")
		b.WriteString(strconv.FormatUint(uint64(*s.GID), 10))
	}
	if encoded {
		b.WriteString(",encoding=base64url")
	}
	return b.String()
}

func equalSpec(a, b Spec) bool {
	return a.Tag == b.Tag && a.Path == b.Path && a.RO == b.RO &&
		a.CtrPath == b.CtrPath && optionalIDEqual(a.UID, b.UID) &&
		optionalIDEqual(a.GID, b.GID)
}

func optionalIDEqual(a, b *uint32) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func perDeviceVMPath(tag string) string { return "/run/mnt/" + tag }

// defaultPerDeviceContainerPath is where the guest bind-mounts a per-device
// share. A single "hostshare" retains the historical /host convention;
// multiple shares live beneath /host/<tag>.
func defaultPerDeviceContainerPath(tag string, multi bool) string {
	if !multi && tag == "hostshare" {
		return HubHostPath
	}
	return HubHostPath + "/" + tag
}

// BuildManifest constructs the per-device manifest for specs.
func BuildManifest(specs []Spec) Manifest {
	manifest := Manifest{Shares: make([]Entry, 0, len(specs))}
	multi := len(specs) > 1
	for _, spec := range specs {
		ctrPath := spec.CtrPath
		if ctrPath == "" {
			ctrPath = defaultPerDeviceContainerPath(spec.Tag, multi)
		}
		manifest.Shares = append(manifest.Shares, Entry{
			Tag:     spec.Tag,
			Path:    spec.Path,
			RO:      spec.RO,
			UID:     spec.UID,
			GID:     spec.GID,
			VMPath:  perDeviceVMPath(spec.Tag),
			CtrPath: ctrPath,
		})
	}
	return manifest
}

// WriteManifest always rewrites the manifest, even when specs is empty, so a
// stale file from a previous boot cannot confuse the guest control plane.
func WriteManifest(path string, specs []Spec) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	payload, err := json.Marshal(BuildManifest(specs))
	if err != nil {
		return err
	}
	return atomicfile.WriteFile(path, append(payload, '\n'), 0o644)
}
