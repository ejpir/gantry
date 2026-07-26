// Package shares defines the virtio-fs share manifest the VMM writes and
// session clients read (<vsockfwd>/shares.json). It exists so internal/vmm
// (writer) and internal/client (reader) share one definition of the JSON
// schema instead of maintaining twin structs.
package shares

// Entry is one exported host directory and where it appears for the guest.
type Entry struct {
	Tag     string `json:"tag"`
	Path    string `json:"path"`
	RO      bool   `json:"ro,omitempty"`
	VMPath  string `json:"vmPath"`
	CtrPath string `json:"ctrPath"`
}

// Manifest is <vsockfwd>/shares.json.
type Manifest struct {
	Shares []Entry `json:"shares"`
}
