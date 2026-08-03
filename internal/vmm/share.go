package vmm

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gantry/internal/shares"
)

// ErrGuestReset signals a guest-initiated reboot via the reset ports.
var ErrGuestReset = fmt.Errorf("guest requested reset via port 0xcf9/0x64")

// Share is one -share TAG=PATH[@CTRPATH][,ro] command-line export.
//
// Read-only semantics are enforced on the host by the virtio-fs backend
// (raw-opcode gate for legacy Unix devices, per-export node gates for the
// hub and Windows backend). hostctl additionally mounts the tag with
// MS_RDONLY and adds "ro" to the OCI bind mount as defense in depth.
type Share struct {
	Tag  string
	Path string
	RO   bool
	// CtrPath overrides the container bind-mount target (default:
	// shareCtrPath — /host or /host/<tag>). `gantry pi` uses it to land
	// the host's ~/.pi/agent at /root/.pi/agent in the guest.
	CtrPath string
}

// ShareManifestEntry is written to <vsockfwd>/shares.json so hostctl can
// mount exactly what the VMM exported without duplicate configuration.
// The schema is shared with the session client via internal/shares.
type ShareManifestEntry = shares.Entry

type ShareManifest = shares.Manifest

func shareVMPath(tag string) string { return "/run/mnt/" + tag }

// shareCtrPath is where crun bind-mounts the share inside the container.
// A single "hostshare" keeps the simple /host convention; anything else
// lives under /host/<tag> (hostctl then mounts a tmpfs at /host so crun
// can create the per-tag mountpoint directories).
func shareCtrPath(tag string, multi bool) string {
	if !multi && tag == "hostshare" {
		return "/host"
	}
	return "/host/" + tag
}

// ParseShareSpec parses TAG=PATH[@CTRPATH][,ro]: the optional @CTRPATH
// (an absolute container path) overrides where crun bind-mounts the
// share; the ,ro suffix is the only other supported option. Splitting only
// on the first '=' leaves Windows drive colons in PATH intact.
func ParseShareSpec(spec string, seen map[string]bool) (Share, error) {
	tag, path, ok := strings.Cut(spec, "=")
	if !ok {
		return Share{}, fmt.Errorf("want TAG=PATH[@CTRPATH][,ro]")
	}
	var ro bool
	if strings.HasSuffix(path, ",ro") {
		ro = true
		path = strings.TrimSuffix(path, ",ro")
	}
	var ctr string
	if i := strings.LastIndex(path, "@"); i >= 0 {
		ctr = path[i+1:]
		path = path[:i]
		if !strings.HasPrefix(ctr, "/") {
			return Share{}, fmt.Errorf("container path after @ must be absolute (got %q)", ctr)
		}
	}
	switch {
	case shares.ValidateShareTag(tag) != nil:
		return Share{}, shares.ValidateShareTag(tag)
	case path == "":
		return Share{}, fmt.Errorf("empty path")
	case seen[tag]:
		return Share{}, fmt.Errorf("duplicate tag %q", tag)
	}
	return Share{Tag: tag, Path: path, RO: ro, CtrPath: ctr}, nil
}

func buildShareManifest(shares []Share) ShareManifest {
	m := ShareManifest{Shares: []ShareManifestEntry{}}
	multi := len(shares) > 1
	for _, s := range shares {
		ctr := s.CtrPath
		if ctr == "" {
			ctr = shareCtrPath(s.Tag, multi)
		}
		m.Shares = append(m.Shares, ShareManifestEntry{
			Tag:     s.Tag,
			Path:    s.Path,
			RO:      s.RO,
			VMPath:  shareVMPath(s.Tag),
			CtrPath: ctr,
		})
	}
	return m
}

// WriteShareManifest always rewrites the manifest (even when empty) so a
// stale file from a previous boot cannot confuse hostctl.
func WriteShareManifest(path string, shares []Share) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.Marshal(buildShareManifest(shares))
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}
