// Package shares defines host-directory export specifications and the
// virtio-fs manifest shared by the CLI, sandbox control plane, VMM assembly,
// and guest session client.
package shares

import "fmt"

// HubTag is the one permanent virtio-fs transport used by persistent
// sandboxes. Logical shares are children beneath HubVMPath, not separate
// virtio devices.
const (
	HubTag          = "gantry-shares"
	HubVMPath       = "/run/mnt/gantry-shares"
	HubInternalPath = "/run/gantry/shares"
	HubHostPath     = "/host"
	ManifestVersion = 2
)

// Transport describes the guest mount that carries every logical share.
type Transport struct {
	Tag    string `json:"tag"`
	VMPath string `json:"vmPath"`
}

// Entry is one exported host directory and where it appears for the guest.
type Entry struct {
	Tag     string  `json:"tag"`
	Path    string  `json:"path"`
	RO      bool    `json:"ro,omitempty"`
	UID     *uint32 `json:"uid,omitempty"`
	GID     *uint32 `json:"gid,omitempty"`
	VMPath  string  `json:"vmPath"`
	CtrPath string  `json:"ctrPath"`
	State   string  `json:"state,omitempty"`
}

// Manifest is <vsockfwd>/shares.json. Version/Generation/Transport are
// omitted by the per-device writer so clients predating the hub protocol keep
// parsing it.
type Manifest struct {
	Version    int        `json:"version,omitempty"`
	Generation uint64     `json:"generation,omitempty"`
	Transport  *Transport `json:"transport,omitempty"`
	Shares     []Entry    `json:"shares"`
}

// MaxTagLen is the virtio-fs mount-tag field bound (FSTagLen).
const MaxTagLen = 36

// ValidateShareTag is the single share-tag validator used by the spec parser
// and the host share service. Tags become
// synthetic FUSE directory entries, so "." and ".." are rejected outright:
// they are reserved directory names and would produce unreachable or
// path-collapsing share definitions.
func ValidateShareTag(tag string) error {
	if tag == "" {
		return fmt.Errorf("share tag is empty")
	}
	if len(tag) > MaxTagLen {
		return fmt.Errorf("share tag %q exceeds %d bytes", tag, MaxTagLen)
	}
	if tag == "." || tag == ".." {
		return fmt.Errorf("share tag %q is a reserved directory entry", tag)
	}
	for _, r := range tag {
		ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-'
		if !ok {
			return fmt.Errorf("share tag %q contains invalid character %q", tag, r)
		}
	}
	return nil
}
