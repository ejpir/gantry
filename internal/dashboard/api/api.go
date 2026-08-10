// Package api defines the data and operations consumed by the local
// dashboard. It intentionally contains no terminal UI dependencies so the
// sandbox control plane can implement Service without importing Bubble Tea.
package api

import (
	"os/exec"
	"time"
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
	Secrets          string
	SecretCount      int
	RW               bool
	Net              bool
	GVProxy          string
	NetPolicy        string
	AllowLocal       bool
	Shares           int
	MemMB            uint
	VCPUs            int
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

type Snapshot struct {
	Sandboxes []Sandbox
	Traffic   []Traffic
	Rules     []Rule
	Mounts    []Mount
	Ports     []Port
}

type ResourceLimits struct {
	MinMemoryMB uint
	MaxMemoryMB uint
	MaxVCPUs    int
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
	ValidateCreate(name string, memMB uint, vcpus int) error
	ValidateResources(memMB uint, vcpus int) error
	SetResources(name string, memMB uint, vcpus int) error
	ValidateNetworkPolicy(path string, allowLocal bool) error
	SetNetworkPolicy(name, path string, allowLocal bool) (PolicyResult, error)
	PlanShare(ShareRequest) (SharePlan, error)
	ConfigureShare(SharePlan) error
	RemoveShare(Mount) error
	PlanPort(PortRequest) (string, error)
}
