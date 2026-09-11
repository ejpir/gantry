// Package watchproto defines the bounded stdout protocol used by the
// guest-side loopback-listener watcher. It is deliberately a leaf package so
// the static gantry-guest binary does not import the host bridge or daemon.
package watchproto

import "time"

const (
	// MaxPorts bounds both guest work and one host-side snapshot.
	MaxPorts = 128
	// MaxMessageBytes bounds one newline-delimited JSON snapshot.
	MaxMessageBytes = 4 << 10
	// PollInterval is short relative to an interactive OAuth flow while keeping
	// procfs polling negligible.
	PollInterval = 200 * time.Millisecond
)

// Snapshot is the complete set of eligible TCP loopback listeners currently
// visible in the guest network namespace. Ports is sorted and deduplicated.
type Snapshot struct {
	Ports []int `json:"ports"`
}
