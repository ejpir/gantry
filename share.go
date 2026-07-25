package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// virtioFSTagLen is the virtio-fs tag length limit from the spec.
const virtioFSTagLen = 36

// errGuestReset signals a guest-initiated reboot via the reset ports.
var errGuestReset = fmt.Errorf("guest requested reset via port 0xcf9/0x64")

// hostShare is one -share TAG=PATH[,ro] command-line export.
//
// Read-only semantics are enforced where Docker enforces them for virtio-fs
// bind mounts too: in the guest. hostctl mounts the tag with MS_RDONLY and
// adds "ro" to the OCI bind mount, so the guest kernel VFS rejects writes
// before they can reach the FUSE server.
type hostShare struct {
	tag  string
	path string
	ro   bool
}

// shareManifestEntry is written to <vsockfwd>/shares.json so hostctl can
// mount exactly what the VMM exported without duplicate configuration.
type shareManifestEntry struct {
	Tag     string `json:"tag"`
	Path    string `json:"path"`
	RO      bool   `json:"ro,omitempty"`
	VMPath  string `json:"vmPath"`
	CtrPath string `json:"ctrPath"`
}

type shareManifest struct {
	Shares []shareManifestEntry `json:"shares"`
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

// parseShareSpec parses TAG=PATH[,ro]. The ,ro suffix is the only supported
// option; a Windows-style drive colon in PATH is not a concern on
// Linux/macOS hosts.
func parseShareSpec(spec string, seen map[string]bool) (hostShare, error) {
	tag, path, ok := strings.Cut(spec, "=")
	if !ok {
		return hostShare{}, fmt.Errorf("want TAG=PATH[,ro]")
	}
	var ro bool
	if strings.HasSuffix(path, ",ro") {
		ro = true
		path = strings.TrimSuffix(path, ",ro")
	}
	switch {
	case !validShareTag(tag):
		return hostShare{}, fmt.Errorf("invalid tag %q (letters, digits, ._-; max %d bytes)", tag, virtioFSTagLen)
	case path == "":
		return hostShare{}, fmt.Errorf("empty path")
	case seen[tag]:
		return hostShare{}, fmt.Errorf("duplicate tag %q", tag)
	}
	return hostShare{tag: tag, path: path, ro: ro}, nil
}

func buildShareManifest(shares []hostShare) shareManifest {
	m := shareManifest{Shares: []shareManifestEntry{}}
	multi := len(shares) > 1
	for _, s := range shares {
		m.Shares = append(m.Shares, shareManifestEntry{
			Tag:     s.tag,
			Path:    s.path,
			RO:      s.ro,
			VMPath:  shareVMPath(s.tag),
			CtrPath: shareCtrPath(s.tag, multi),
		})
	}
	return m
}

// writeShareManifest always rewrites the manifest (even when empty) so a
// stale file from a previous boot cannot confuse hostctl.
func writeShareManifest(path string, shares []hostShare) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.Marshal(buildShareManifest(shares))
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}
