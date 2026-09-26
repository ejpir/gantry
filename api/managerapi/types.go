package managerapi

import (
	"encoding/json"
	"time"

	"github.com/ejpir/gantry/internal/policy"
	"github.com/ejpir/gantry/internal/sandbox/control"
	"github.com/ejpir/gantry/internal/sandbox/inspection"
)

// The types in this file are the canonical Go definition of the manager's
// wire protocol: they mirror components.schemas in openapi.yaml and are
// shared by the server (internal/sandbox/manager) and remote clients
// (internal/remote). The contract test in the manager package keeps the two
// representations in lockstep, so a schema change starts here.

// Health is GET /v1/health.
type Health struct {
	OK           bool     `json:"ok"`
	Version      string   `json:"version"`
	Capabilities []string `json:"capabilities,omitempty"`
}

// ErrorResponse is the failure body for every endpoint.
type ErrorResponse struct {
	Error       string `json:"error"`
	OperationID string `json:"operationId,omitempty"`
}

// PolicyFeedPrepareRequest binds a host-generated CSR to the service trust
// selected by the administrator. None of these fields are private keys.
type PolicyFeedPrepareRequest struct {
	Host                 string `json:"host"`
	Organization         string `json:"organization"`
	Profile              string `json:"profile"`
	URL                  string `json:"url"`
	PublicKeyFingerprint string `json:"publicKeyFingerprint"`
	CAFingerprint        string `json:"caFingerprint"`
}

type PolicyFeedPrepareResponse struct {
	ID  string `json:"id"`
	CSR string `json:"csr"`
}

// PolicyFeedInstallRequest contains only the four public enrollment files.
type PolicyFeedInstallRequest struct {
	ID    string            `json:"id"`
	Files map[string]string `json:"files"`
}

// PolicyFeedStatus never exposes the host's private key or certificate request.
type PolicyFeedStatus struct {
	EnrollmentState string `json:"state"`
	Host            string `json:"host,omitempty"`
	Organization    string `json:"organization,omitempty"`
	Profile         string `json:"profile,omitempty"`
	ConfigPath      string `json:"configPath,omitempty"`
}

// Sandbox is the reported state of one sandbox.
type Sandbox struct {
	Desired         inspection.BootSettings  `json:"desired"`
	Active          *inspection.BootSettings `json:"active,omitempty"`
	RestartRequired bool                     `json:"restartRequired"`
	Name            string                   `json:"name"`
	State           string                   `json:"state"`
	PID             int                      `json:"pid,omitempty"`
	Image           string                   `json:"image,omitempty"`
	ImageRef        string                   `json:"imageRef,omitempty"`
	ImageDigest     string                   `json:"imageDigest,omitempty"`
	CPUs            int                      `json:"cpus,omitempty"`
	MemoryMiB       uint                     `json:"memoryMiB,omitempty"`
	Writable        bool                     `json:"writable"`
	Proxy           string                   `json:"proxy,omitempty"`
	NoProxy         string                   `json:"noProxy,omitempty"`
	ProxyEnforce    bool                     `json:"proxyEnforce,omitempty"`
}

// CreateSandboxRequest is POST /v1/sandboxes. Zero values are omitted so the
// manager's defaults apply; secret NAMES only — values are resolved from the
// manager's own environment and are never accepted over HTTP. An active
// organization-wide feed snapshot is inherited rather than client-selectable.
type CreateSandboxRequest struct {
	OrganizationPolicy *policy.Config `json:"organizationPolicy,omitempty"`
	Name               string         `json:"name"`
	Image              string         `json:"image"`
	Kernel             string         `json:"kernel,omitempty"`
	Rootfs             string         `json:"rootfs,omitempty"`
	Runtime            string         `json:"runtime,omitempty"`
	RW                 *bool          `json:"rw,omitempty"`
	RWLayer            string         `json:"rwlayer,omitempty"`
	Shares             []string       `json:"shares,omitempty"`
	Publish            []string       `json:"publish,omitempty"`
	Net                *bool          `json:"net,omitempty"`
	NetworkPolicy      string         `json:"networkPolicy,omitempty"`
	AllowLocalNetwork  bool           `json:"allowLocalNetwork,omitempty"`
	Proxy              string         `json:"proxy,omitempty"`
	NoProxy            string         `json:"noProxy,omitempty"`
	ProxyEnforce       bool           `json:"proxyEnforce,omitempty"`
	OAuthBridge        *bool          `json:"oauthBridge,omitempty"`
	ProcessIsolation   string         `json:"processIsolation,omitempty"`
	MemoryMiB          uint           `json:"memoryMiB,omitempty"`
	DiskSizeMiB        uint           `json:"diskSizeMiB,omitempty"`
	CPUs               int            `json:"cpus,omitempty"`
	SecretNames        []string       `json:"secretNames,omitempty"`
	SSH                bool           `json:"ssh,omitempty"`
	DevContainers      bool           `json:"devContainers,omitempty"`
}

// ConfigureSandboxRequest is a partial update. Pointers preserve omission
// versus explicitly false/zero; no host paths or private configuration escape.
type ConfigureSandboxRequest struct {
	SSH              *bool   `json:"ssh,omitempty"`
	DevContainers    *bool   `json:"devContainers,omitempty"`
	MemoryMiB        *uint   `json:"memoryMiB,omitempty"`
	CPUs             *int    `json:"cpus,omitempty"`
	ProcessIsolation *string `json:"processIsolation,omitempty"`
}

type ConfigureSandboxResult struct {
	RestartRequired bool `json:"restartRequired"`
}

// RunVMRequest is the low-level kernel/disk launcher, NOT a named sandbox
// create or an arbitrary command. All paths refer to the manager host.
// Optional switch pointers preserve explicit false and an empty listen list.
type RunVMRequest struct {
	Kernel          string   `json:"kernel"`
	Initrd          string   `json:"initrd,omitempty"`
	Rootfs          string   `json:"rootfs,omitempty"`
	Disks           []string `json:"disks,omitempty"`
	Shares          []string `json:"shares,omitempty"`
	NetworkEndpoint string   `json:"networkEndpoint,omitempty"`
	NetworkMAC      string   `json:"networkMAC,omitempty"`
	NetworkVFKIT    *bool    `json:"networkVFKIT,omitempty"`
	NetworkDHCP     *bool    `json:"networkDHCP,omitempty"`
	VsockForward    string   `json:"vsockForward,omitempty"`
	VsockListen     *string  `json:"vsockListen,omitempty"`
	GuestCID        uint64   `json:"guestCID,omitempty"`
	MemoryMiB       uint     `json:"memoryMiB,omitempty"`
	CPUs            int      `json:"cpus,omitempty"`
	CommandLine     string   `json:"commandLine,omitempty"`
	Stdin           string   `json:"stdin,omitempty"`
	TimeoutSeconds  int      `json:"timeoutSeconds,omitempty"`
	MaxOutputBytes  int      `json:"maxOutputBytes,omitempty"`
}

// NetworkPolicy is the existing control protocol's effective policy summary.
type NetworkPolicy = control.NetworkPolicyEntry

// NetworkPolicyRequest carries policy data, not a client filesystem path.
type NetworkPolicyRequest struct {
	Policy     json.RawMessage `json:"policy,omitempty"`
	Default    bool            `json:"default,omitempty"`
	AllowLocal bool            `json:"allowLocal,omitempty"`
}

// OrganizationPolicyRequest accepts only a signed data bundle and PUBLIC key.
// The canonical policy.Config is shared with the local verification path.
// Per-sandbox mutations are refused while a manager-wide feed is active.
type OrganizationPolicyRequest struct {
	Snapshot *policy.Config `json:"snapshot,omitempty"`
	Clear    bool           `json:"clear,omitempty"`
	// Restart explicitly selects controlled stop/update/resume. Without it, a
	// running sandbox reconciles the policy across live enforcement points.
	Restart bool `json:"restart,omitempty"`
}

type OrganizationPolicy struct {
	Managed bool                 `json:"managed"`
	Info    *policy.SnapshotInfo `json:"info,omitempty"`
}

type AuditTail struct {
	Lines []string `json:"lines"`
}

// SSHHostKey contains the public half of the install identity, never its signer.
type SSHHostKey struct {
	PublicKey string `json:"publicKey"`
}

// ExecRequest is POST /v1/sandboxes/{name}/exec: one bounded, non-interactive
// command execution.
type ExecRequest struct {
	Argv           []string `json:"argv"`
	Cwd            string   `json:"cwd,omitempty"`
	Stdin          string   `json:"stdin,omitempty"`
	TimeoutSeconds int      `json:"timeoutSeconds,omitempty"`
	MaxOutputBytes int64    `json:"maxOutputBytes,omitempty"`
}

// ExecResult is the bounded output of a finished command. A non-zero process
// exit code is still a 200 response.
type ExecResult struct {
	ExitCode  int    `json:"exitCode"`
	Output    string `json:"output"`
	Truncated bool   `json:"truncated"`
}

// Operation is a lifecycle operation record. Lifecycle calls answer
// synchronously with the finished operation; pulls and in-flight replays
// return the running state for polling.
type Operation struct {
	ID        string                  `json:"id"`
	Kind      string                  `json:"kind"`
	Sandbox   string                  `json:"sandbox,omitempty"`
	State     string                  `json:"state"`
	Error     string                  `json:"error,omitempty"`
	Warnings  []string                `json:"warnings,omitempty"`
	Configure *ConfigureSandboxResult `json:"configure,omitempty"`
	// Run holds bounded console output. Exit 124 means the VM hit its
	// deadline; 130 means it was canceled. Nonzero process exits still
	// complete the operation, as for captured exec.
	Run *ExecResult `json:"run,omitempty"`
	// Progress is the latest progress line while the operation runs and a
	// short summary once it succeeded (long-running operations such as
	// image pulls update it between polls).
	Progress string    `json:"progress,omitempty"`
	Created  time.Time `json:"createdAt"`
	Updated  time.Time `json:"updatedAt"`
}

// Image is one entry of the manager host's image cache (GET /v1/images).
// Fields mirror the image store's on-disk metadata.
type Image struct {
	Ref     string `json:"ref"`
	Digest  string `json:"digest"`
	Arch    string `json:"arch"`
	Size    int64  `json:"size"`
	Created string `json:"created"`
}

// ImageList is the cache listing response.
type ImageList struct {
	Images []Image `json:"images"`
}

// ImagePullRequest resolves and builds an image into the manager host's
// cache (POST /v1/images/pull). Pulls run asynchronously: the response is
// a running Operation to poll.
type ImagePullRequest struct {
	Ref string `json:"ref"`
	// Platform is the target architecture ("arm64", "linux/arm64", ...);
	// empty means the manager host's own architecture.
	Platform string `json:"platform,omitempty"`
}

// ImageDeleteRequest removes one cached image (POST /v1/images/delete).
type ImageDeleteRequest struct {
	Ref string `json:"ref"`
}

// Event is one entry of the GET /v1/events SSE stream.
type Event struct {
	ID          uint64    `json:"id"`
	Type        string    `json:"type"`
	OperationID string    `json:"operationId,omitempty"`
	Sandbox     string    `json:"sandbox,omitempty"`
	State       string    `json:"state,omitempty"`
	Time        time.Time `json:"time"`
}
