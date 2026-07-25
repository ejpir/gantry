package vmm

import (
	"encoding/json"
	"fmt"
	"gantry/internal/virtio"
	"os"
	"path/filepath"
	"strings"
)

// virtioFSTagLen is the virtio-fs tag length limit from the spec.
const virtioFSTagLen = virtio.FSTagLen

// ErrGuestReset signals a guest-initiated reboot via the reset ports.
var ErrGuestReset = fmt.Errorf("guest requested reset via port 0xcf9/0x64")

// Share is one -share TAG=PATH[,ro] command-line export.
//
// Read-only semantics are enforced where Docker enforces them for virtio-fs
// bind mounts too: in the guest. hostctl mounts the tag with MS_RDONLY and
// adds "ro" to the OCI bind mount, so the guest kernel VFS rejects writes
// before they can reach the FUSE server.
type Share struct {
	Tag  string
	Path string
	RO   bool
}

// ShareManifestEntry is written to <vsockfwd>/shares.json so hostctl can
// mount exactly what the VMM exported without duplicate configuration.
type ShareManifestEntry struct {
	Tag     string `json:"tag"`
	Path    string `json:"path"`
	RO      bool   `json:"ro,omitempty"`
	VMPath  string `json:"vmPath"`
	CtrPath string `json:"ctrPath"`
}

type ShareManifest struct {
	Shares []ShareManifestEntry `json:"shares"`
}

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

// ParseShareSpec parses TAG=PATH[,ro]. The ,ro suffix is the only supported
// option; a Windows-style drive colon in PATH is not a concern on
// Linux/macOS hosts.
func ParseShareSpec(spec string, seen map[string]bool) (Share, error) {
	tag, path, ok := strings.Cut(spec, "=")
	if !ok {
		return Share{}, fmt.Errorf("want TAG=PATH[,ro]")
	}
	var ro bool
	if strings.HasSuffix(path, ",ro") {
		ro = true
		path = strings.TrimSuffix(path, ",ro")
	}
	switch {
	case !validShareTag(tag):
		return Share{}, fmt.Errorf("invalid tag %q (letters, digits, ._-; max %d bytes)", tag, virtioFSTagLen)
	case path == "":
		return Share{}, fmt.Errorf("empty path")
	case seen[tag]:
		return Share{}, fmt.Errorf("duplicate tag %q", tag)
	}
	return Share{Tag: tag, Path: path, RO: ro}, nil
}

func buildShareManifest(shares []Share) ShareManifest {
	m := ShareManifest{Shares: []ShareManifestEntry{}}
	multi := len(shares) > 1
	for _, s := range shares {
		m.Shares = append(m.Shares, ShareManifestEntry{
			Tag:     s.Tag,
			Path:    s.Path,
			RO:      s.RO,
			VMPath:  shareVMPath(s.Tag),
			CtrPath: shareCtrPath(s.Tag, multi),
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

func validShareTag(tag string) bool {
	if tag == "" || len([]byte(tag)) > virtioFSTagLen {
		return false
	}
	for _, r := range tag {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}
