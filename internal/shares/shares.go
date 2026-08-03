// Package shares defines the virtio-fs share manifest the VMM writes and
// session clients read (<vsockfwd>/shares.json). It exists so internal/vmm
// (writer) and internal/client (reader) share one definition of the JSON
// schema instead of maintaining twin structs.
package shares

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
	Tag     string `json:"tag"`
	Path    string `json:"path"`
	RO      bool   `json:"ro,omitempty"`
	VMPath  string `json:"vmPath"`
	CtrPath string `json:"ctrPath"`
	State   string `json:"state,omitempty"`
}

// Manifest is <vsockfwd>/shares.json. Version/Generation/Transport are
// omitted by the legacy per-device writer so old clients keep parsing it.
type Manifest struct {
	Version    int        `json:"version,omitempty"`
	Generation uint64     `json:"generation,omitempty"`
	Transport  *Transport `json:"transport,omitempty"`
	Shares     []Entry    `json:"shares"`
}
