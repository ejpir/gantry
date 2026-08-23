package networkworker

import (
	"encoding/json"

	"github.com/ejpir/gantry/internal/netpol"
	"github.com/ejpir/gantry/internal/workerconf"
)

// Operations are private to the supervisor↔network-worker control channel.
const (
	OpPolicyPrepare   = "policy.prepare"
	OpPolicyCommit    = "policy.commit"
	OpPolicyAbort     = "policy.abort"
	OpPolicyStatus    = "policy.status"
	OpPortPublish     = "port.publish"
	OpPortUnpublish   = "port.unpublish"
	OpPortStatus      = "port.status"
	OpPortList        = "port.list"
	OpTrafficSnapshot = "traffic.snapshot"
	OpCapture         = "capture.read"
	OpShutdown        = "shutdown"
)

// PolicyState is the worker's view of a policy transaction.
type PolicyState string

const (
	PolicyStateCurrent   PolicyState = "current"
	PolicyStatePrepared  PolicyState = "prepared"
	PolicyStateCommitted PolicyState = "committed"
	PolicyStateUnknown   PolicyState = "unknown"
)

// Config is the normalized bootstrap payload sent by the supervisor. ConfRoot
// is the supervisor-created private-root mountpoint.
type Config struct {
	GuestMAC                string            `json:"guest_mac"`
	Forwards                map[string]string `json:"forwards,omitempty"`
	Policy                  json.RawMessage   `json:"policy"`
	Debug                   bool              `json:"debug"`
	Confinement             string            `json:"confinement"`
	ConfRoot                string            `json:"conf_root,omitempty"`
	HostLoopbackUnavailable bool              `json:"host_loopback_unavailable,omitempty"`
}

type BootAck struct {
	OK          bool               `json:"ok"`
	Error       string             `json:"error,omitempty"`
	Confinement *workerconf.Report `json:"confinement,omitempty"`
}

type ShutdownResponse struct {
	Traffic *netpol.TrafficSnapshot `json:"traffic,omitempty"`
}

type PolicyPrepareRequest struct {
	Generation  uint64          `json:"generation"`
	Transaction string          `json:"transaction"`
	Policy      json.RawMessage `json:"policy"`
}

type PolicyGenerationRequest struct {
	Generation  uint64 `json:"generation,omitempty"`
	Transaction string `json:"transaction,omitempty"`
}

type PolicyStatusResponse struct {
	State              PolicyState `json:"state"`
	Generation         uint64      `json:"generation"`
	Transaction        string      `json:"transaction,omitempty"`
	PendingGeneration  uint64      `json:"pending_generation,omitempty"`
	PendingTransaction string      `json:"pending_transaction,omitempty"`
}

type PortPublishRequest struct {
	Transaction string `json:"transaction"`
	Proto       string `json:"proto"`
	Local       string `json:"local"`
	Remote      string `json:"remote"`
}

type PortUnpublishRequest struct {
	Transaction string `json:"transaction"`
	Proto       string `json:"proto"`
	Local       string `json:"local"`
}

type PortStatusRequest struct {
	Transaction string `json:"transaction"`
}

type PortState string

const (
	PortStateApplied  PortState = "applied"
	PortStateRejected PortState = "rejected"
	PortStateUnknown  PortState = "unknown"
)

type PortStatusResponse struct {
	Transaction string    `json:"transaction"`
	State       PortState `json:"state"`
	Error       string    `json:"error,omitempty"`
}
