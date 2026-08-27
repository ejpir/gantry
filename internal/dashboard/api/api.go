// Package api defines the data and operations consumed by the local
// dashboard. It intentionally contains no terminal UI dependencies so the
// sandbox control plane can implement Service without importing Bubble Tea.
package api

import (
	"os/exec"
	"time"

	"github.com/ejpir/gantry/internal/packetcapture"
	"github.com/ejpir/gantry/internal/secret"
)

type SandboxState string

const (
	Stopped  SandboxState = "stopped"
	Starting SandboxState = "starting"
	Running  SandboxState = "running"
)

type Sandbox struct {
	Name             string
	State            SandboxState
	PID              int
	Image            string
	Runtime          string
	Kernel           string
	Secrets          string
	SecretCount      int
	RW               bool
	RWLayer          string
	DiskSizeMiB      uint
	Net              bool
	GVProxy          string
	NetPolicy        string
	AllowLocal       bool
	Proxy            string
	NoProxy          string
	ProxyEnforce     bool
	Shares           int
	Ports            int
	MemMB            uint
	VCPUs            int
	ProcessIsolation string
	SSH              bool
	DevContainers    bool
	Dir              string
	ConfigPath       string
	Updated          time.Time
	ConfigError      bool
	TXBytes          uint64
	RXBytes          uint64
	DroppedPackets   uint64
	TrafficAvailable bool
}

type Traffic struct {
	Sandbox   string
	Host      string
	Address   string
	Protocol  string
	Port      uint16
	Allowed   bool
	TXBytes   uint64
	RXBytes   uint64
	TXPackets uint64
	RXPackets uint64
	FirstSeen time.Time
	LastSeen  time.Time
}

type Rule struct {
	Sandbox string
	Action  string
	Target  string
	Proto   string
	Ports   string
	Source  string
	Policy  string
	Error   bool
}

type RuleRequest struct {
	Sandbox string
	Action  string
	Target  string
	Proto   string
	Ports   string
}

type Mount struct {
	Sandbox  string
	Tag      string
	Host     string
	VM       string
	Guest    string
	ReadOnly bool
	UID      *uint32
	GID      *uint32
	State    string
	Error    string
}

type Port struct {
	Sandbox string
	Bind    string
	Guest   int
	Proto   string
	State   string
	Error   string
}

type Secret struct {
	Sandbox string
	Name    string
	State   string
}

type SecretRequest struct {
	Sandbox string
	Name    string
	Value   secret.Value
}

// Image is one cached OCI image in the local image store. Entrypoint, Cmd,
// and EnvCount describe the image config captured at build time.
type Image struct {
	Ref        string
	Digest     string
	Arch       string
	Created    string
	Size       int64
	InUse      bool // a sandbox config references this digest
	User       string
	WorkingDir string
	Entrypoint []string
	Cmd        []string
	EnvCount   int
}

// RegistryAuth describes the credential resolution for one registry. The
// secret value itself never crosses the dashboard boundary: HasSecret only
// reports that one exists.
type RegistryAuth struct {
	Registry  string
	Username  string
	Source    string
	HasSecret bool
}

// RegistryLoginRequest carries a registry credential to store. Secret is
// write-only: it is persisted (helper or 0600 file) and then dropped.
type RegistryLoginRequest struct {
	Registry string
	Username string
	Secret   secret.Value
}

// MCPServer contains configuration references only. AuthRef and Redact are
// secret/custody names; credential values never cross the dashboard boundary.
type MCPServer struct {
	Sandbox    string
	Name       string
	Type       string // local or remote
	URL        string
	AuthKind   string
	AuthHeader string
	AuthRef    string
	Allow      []string
	Deny       []string
	Redact     []string
	Root       string
	User       string
	State      string // active, saved, or restart
	Error      string
}

type MCPRemoteRequest struct {
	Sandbox    string
	Name       string
	URL        string
	AuthKind   string
	AuthHeader string
	AuthRef    string
	Allow      []string
	Deny       []string
	Redact     []string
	Replace    bool
}

type MCPFilesystemRequest struct {
	Sandbox string
	Root    string
	User    string
}

type Snapshot struct {
	Sandboxes  []Sandbox
	Traffic    []Traffic
	Rules      []Rule
	Mounts     []Mount
	Ports      []Port
	Secrets    []Secret
	MCPServers []MCPServer
	Images     []Image
	Registries []RegistryAuth
}

type ResourceLimits struct {
	MinMemoryMB                   uint
	MaxMemoryMB                   uint
	MinDiskSizeMiB                uint
	MaxDiskSizeMiB                uint
	DefaultDiskSizeMiB            uint
	MaxVCPUs                      int
	DefaultDevContainersMemoryMiB uint
	DefaultDevContainersDiskMiB   uint
	DefaultDevContainersVCPUs     int
}

type SandboxConfigRequest struct {
	Name             string
	MemMB            uint
	VCPUs            int
	ProcessIsolation string
	SSH              bool
	DevContainers    bool
}

type PolicyResult struct {
	Path        string
	Description string
}

type ShareRequest struct {
	Sandbox      string
	Tag          string
	Path         string
	Mountpoint   string
	Owner        string
	ReadOnly     bool
	Replace      bool
	Running      bool
	CurrentGuest string
}

type SharePlan struct {
	Sandbox    string
	Tag        string
	Spec       string
	Mountpoint string
	Replace    bool
	Live       bool
}

type PortRequest struct {
	Bind  string
	Guest string
	UDP   bool
}

// FieldError lets forms focus the invalid input without coupling the service
// to any terminal UI implementation.
type FieldError struct {
	Field string
	Err   error
}

func (e *FieldError) Error() string { return e.Err.Error() }
func (e *FieldError) Unwrap() error { return e.Err }

func Invalid(field string, err error) error {
	if err == nil {
		return nil
	}
	return &FieldError{Field: field, Err: err}
}

// Service is the dashboard's complete control-plane boundary. Implementations
// own sandbox storage, validation, and broker RPCs; the dashboard owns only
// interaction and presentation state.
type Service interface {
	Snapshot() (Snapshot, error)
	Command(argv ...string) (*exec.Cmd, error)
	ResourceLimits() ResourceLimits
	KernelChoices() []string
	DefaultShareMount(tag string) string
	ValidateCreate(name string, memMB, diskSizeMiB uint, vcpus int, processIsolation string) error
	ValidateResources(memMB uint, vcpus int, processIsolation string) error
	SetResources(name string, memMB uint, vcpus int, processIsolation string) error
	ValidateSandboxConfig(SandboxConfigRequest) error
	ConfigureSandbox(SandboxConfigRequest) (restartRequired bool, err error)
	ValidateNetworkPolicy(path string, allowLocal bool) error
	SetNetworkPolicy(name, path string, allowLocal bool) (PolicyResult, error)
	ValidateNetworkRule(RuleRequest) error
	AddNetworkRule(RuleRequest) error
	RemoveNetworkRule(Rule) error
	RemoveTrafficRule(Traffic) error
	ValidateSecret(SecretRequest) error
	AddSecret(SecretRequest) error
	RemoveSecret(Secret) error
	ValidateMCPRemote(MCPRemoteRequest) error
	ConfigureMCPRemote(MCPRemoteRequest) error
	ValidateMCPFilesystem(MCPFilesystemRequest) error
	ConfigureMCPFilesystem(MCPFilesystemRequest) error
	RemoveMCPRemote(MCPServer) error
	RemoveImage(refOrDigest string) error
	PruneImages() (int, error)
	ValidateRegistryLogin(RegistryLoginRequest) error
	StoreRegistryLogin(RegistryLoginRequest) (warning string, err error)
	RemoveRegistryLogin(registry string) error
	PlanShare(ShareRequest) (SharePlan, error)
	ConfigureShare(SharePlan) error
	RemoveShare(Mount) error
	PlanPort(PortRequest) (string, error)
	CapturePackets(name string, request packetcapture.Request) (packetcapture.Snapshot, error)
}
