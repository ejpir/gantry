// Package vmmworker runs the untrusted VMM child process.
//
// The worker owns the hypervisor, guest memory, and virtio devices. It receives
// only pre-opened boot assets and bounded broker connections; host share paths,
// root handles, and mutable supervisor state never cross this boundary.
package vmmworker

import (
	"net"
	"os"

	"github.com/ejpir/gantry/internal/netpol"
	"github.com/ejpir/gantry/internal/workerconf"
)

// Config is the authenticated bootstrap payload sent in the worker handshake.
// Descriptor counts define the inherited asset-table layout.
type Config struct {
	MemSize  uint64  `json:"memSize"`
	VCPUs    int     `json:"vcpus"`
	Cmdline  string  `json:"cmdline"`
	NetMAC   [6]byte `json:"netMAC"`
	GuestCID uint64  `json:"guestCID"`
	HasRoot  bool    `json:"hasRootfs"`

	// BootTimingStartUnixNano carries the supervisor's diagnostic clock into
	// the worker. Zero disables guest milestone collection.
	BootTimingStartUnixNano int64  `json:"bootTimingStartUnixNano,omitempty"`
	NDisksRO                int    `json:"nDisksRO"`
	NDisks                  int    `json:"nDisks"`
	DisksPrelocked          bool   `json:"disksPrelocked,omitempty"`
	MaxWritableFileSize     uint64 `json:"maxWritableFileSize,omitempty"`

	// Policy is present only when the worker-side virtio-net device is the
	// enforcement point. Empty policy means a separate network worker owns it.
	Policy []byte `json:"policy,omitempty"`

	// Confinement controls worker self-confinement: auto, required, or off.
	// ConfRoot is the supervisor-created private root on Linux. HasKVM marks a
	// pre-opened hypervisor descriptor at the end of the asset table.
	Confinement string `json:"confinement,omitempty"`
	ConfRoot    string `json:"confRoot,omitempty"`
	HasKVM      bool   `json:"hasKVM,omitempty"`
}

// Assets contains the pre-opened capabilities consumed by the child. ShareConn
// carries bounded FUSE messages and intentionally conveys no host filesystem
// descriptor or path.
type Assets struct {
	ShareConn net.Conn
	NetConn   net.Conn
	Console   *os.File
	Kernel    *os.File
	Rootfs    *os.File
	DisksRO   []*os.File
	Disks     []*os.File
	KVM       *os.File
}

// AssetLoader reconstructs the inherited descriptor table after Config has
// been authenticated. Runtime takes ownership of every non-nil capability in
// the returned Assets value even when the loader also returns an error.
type AssetLoader func(Config) (Assets, error)

// BootAck commits the descriptor ownership handoff only after VMM preparation
// and confinement verification have both completed.
type BootAck struct {
	OK          bool              `json:"ok"`
	Error       string            `json:"error,omitempty"`
	Confinement workerconf.Report `json:"confinement"`
}

// PolicyRequest replaces the worker-side enforcement policy.
type PolicyRequest struct {
	Policy []byte `json:"policy"`
}

// ForwardRequest asks the trusted supervisor to connect a guest-originated
// vsock stream to its host-side listener.
type ForwardRequest struct {
	Port  uint32 `json:"port"`
	Token string `json:"token"`
}

// ConnectRequest correlates a supervisor-transferred stream descriptor with a
// guest vsock port.
type ConnectRequest struct {
	Port  uint32 `json:"port"`
	Token string `json:"token"`
}

// WaitResponse reports VM termination and the final traffic counters while
// the worker control channel is still alive.
type WaitResponse struct {
	Error   string                  `json:"err,omitempty"`
	Traffic *netpol.TrafficSnapshot `json:"traffic,omitempty"`
}

// CloseResponse returns final traffic counters after devices have flushed.
type CloseResponse struct {
	Traffic *netpol.TrafficSnapshot `json:"traffic,omitempty"`
	Error   string                  `json:"error,omitempty"`
}
