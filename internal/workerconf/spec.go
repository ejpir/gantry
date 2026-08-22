// Package workerconf confines a re-executed worker process after it has
// consumed its descriptor table and before it opens the hypervisor.
// See docs/worker-confinement.md: one platform-neutral contract (Spec),
// per-platform enforcers (Apply), and one shared in-worker verifier
// (Verify) so isolation.json reports VERIFIED properties rather than
// platform claims.
package workerconf

// SyscallProfile selects the ambient kernel capabilities a worker role needs.
// The zero value is deliberately the narrower VMM profile so a partially
// initialized Spec cannot accidentally acquire socket-creation authority.
type SyscallProfile uint8

const (
	ProfileVMM SyscallProfile = iota
	ProfileNetwork
	// ProfileMCP permits descriptor I/O and receiving supervisor-brokered
	// connected streams, but no socket creation, path opens, exec, or ioctls.
	ProfileMCP
)

// Spec is the worker's declared ambient-authority requirement. One
// definition, consumed by every platform enforcer.
type Spec struct {
	Profile    SyscallProfile
	NoNetwork  bool // no inbound/outbound sockets ever
	NoExec     bool // no exec/spawn of any program
	NoNewPaths bool // no undeclared host-path access after Apply
	NoProcX    bool // no cross-process ptrace/signal/enumeration
	KeepFDs    int  // descriptors 0..KeepFDs survive Apply (the fd table is dense)
	// MaxTasks bounds Linux threads/processes in the worker's dedicated user
	// namespace via RLIMIT_NPROC after setup capabilities are dropped. Zero
	// disables the tier. Namespace-less auto fallback reports it unenforced.
	MaxTasks uint64
	// KeepFDExtra lists additional LIVE descriptors that must survive
	// the close tier: the net.FileConn dups of the inherited channel
	// conns land ABOVE the dense table (a dup takes the first free fd),
	// and closing them severs the control/data channels mid-boot
	// (AL2023 field failure: close_range killed the control dup, the
	// supervisor EOF'd and SIGKILLed the healthy worker).
	KeepFDExtra []int
	ConfRoot    string // linux: supervisor-created mountpoint for the private root

	// ReadFiles lists immutable host configuration files required by the
	// worker's role. The network role uses only resolver configuration. Linux
	// copies these into its private tmpfs root before pivot_root; Seatbelt grants
	// literal read access. No directory subtree is delegated.
	ReadFiles []string

	// FileAllow is retained for worker roles that intentionally need host
	// path access. The VMM worker leaves it empty: shares are served by the
	// trusted supervisor over a request-only relay. Seatbelt bakes any
	// entries into its immutable profile; Linux ignores this v1.
	FileAllow []FileAllowance
}

// FileAllowance is one allowed host-path subtree.
type FileAllowance struct {
	Path  string
	Write bool // false = read-only export
}

// DefaultSpec is the full deny-everything contract for a VMM worker:
// after the fd table is consumed the worker needs its descriptors,
// anonymous memory, the hypervisor fd, and nothing else.
func DefaultSpec(keepFDs int, confRoot string) Spec {
	return Spec{
		Profile:    ProfileVMM,
		NoNetwork:  true,
		NoExec:     true,
		NoNewPaths: true,
		NoProcX:    true,
		KeepFDs:    keepFDs,
		MaxTasks:   DefaultWorkerTaskLimit,
		ConfRoot:   confRoot,
	}
}

// NetworkSpec is the network worker contract. It necessarily retains IPv4 and
// IPv6 stream/datagram socket authority so the embedded stack can proxy guest
// traffic and host port forwards. It retains no general host filesystem,
// executable, cross-process, raw-socket, or device-ioctl authority.
func NetworkSpec(keepFDs int, confRoot string) Spec {
	return Spec{
		Profile:    ProfileNetwork,
		NoExec:     true,
		NoNewPaths: true,
		NoProcX:    true,
		KeepFDs:    keepFDs,
		MaxTasks:   DefaultWorkerTaskLimit,
		ConfRoot:   confRoot,
		ReadFiles: []string{
			"/etc/hosts",
			"/etc/nsswitch.conf",
			"/etc/resolv.conf",
		},
	}
}

// MCPSpec is the fixed MCP parsing-worker contract. Host destinations,
// credentials, local upstream processes, and connected streams are brokered
// by the supervisor, so the worker needs no ambient network, filesystem,
// execution, device-ioctl, or cross-process authority.
func MCPSpec(keepFDs int, confRoot string) Spec {
	return Spec{
		Profile:    ProfileMCP,
		NoNetwork:  true,
		NoExec:     true,
		NoNewPaths: true,
		NoProcX:    true,
		KeepFDs:    keepFDs,
		MaxTasks:   DefaultWorkerTaskLimit,
		ConfRoot:   confRoot,
	}
}

func validProfile(profile SyscallProfile) bool {
	switch profile {
	case ProfileVMM, ProfileNetwork, ProfileMCP:
		return true
	default:
		return false
	}
}

// DefaultWorkerTaskLimit leaves ample room for Go runtime, cgo, vCPU, and
// packet-processing threads while bounding a compromised worker's host task
// consumption. Each split worker gets an independent user namespace and cap.
const DefaultWorkerTaskLimit = 256

// Property states reported by Verify. "indeterminate" is never silently
// upgraded: a probe that cannot run says so.
const (
	StateEnforced      = "enforced"
	StateUnenforced    = "unenforced"
	StateUnavailable   = "unavailable"
	StateIndeterminate = "indeterminate"
	StateDisabled      = "disabled"
)

// Property names. The same names appear on every platform so
// isolation.json and the TUI can render a uniform matrix.
const (
	PropFSRead     = "fs-read"
	PropFSWrite    = "fs-write"
	PropNetDial    = "net-dial"
	PropExec       = "exec"
	PropProcEnum   = "proc-enum"
	PropProcSignal = "proc-signal"
	PropTaskLimit  = "task-limit"
	PropSyscall    = "syscall-policy"
	PropLandlock   = "landlock"
	PropFDTable    = "fd-table"
)

// PropertyResult is one verified confinement property.
type PropertyResult struct {
	Property string `json:"name"`
	State    string `json:"state"`
	Detail   string `json:"detail,omitempty"`
}

// Report is what Apply installed plus what Verify proved. It rides the
// worker's boot ack to the supervisor, which writes isolation.json.
type Report struct {
	Platform string           `json:"platform"`
	Mode     string           `json:"mode"` // auto | required | off
	Applied  bool             `json:"applied"`
	Notes    []string         `json:"notes,omitempty"`
	Results  []PropertyResult `json:"properties"`
}

// Property returns the result for one property name.
func (r *Report) Property(name string) PropertyResult {
	for _, p := range r.Results {
		if p.Property == name {
			return p
		}
	}
	return PropertyResult{Property: name, State: StateUnavailable}
}

// Failed returns the names of the given properties that are not
// verified enforced; the caller (required mode) refuses the boot when
// the list is non-empty.
func (r *Report) Failed(required ...string) []string {
	var failed []string
	for _, name := range required {
		if r.Property(name).State != StateEnforced {
			failed = append(failed, name)
		}
	}
	return failed
}

// DisabledReport is the report for mode "off" (and for platforms whose
// enforcer is not implemented yet): every property honestly disabled.
func DisabledReport(platform, mode string) Report {
	results := []PropertyResult{
		{Property: PropFSRead, State: StateDisabled},
		{Property: PropFSWrite, State: StateDisabled},
		{Property: PropNetDial, State: StateDisabled},
		{Property: PropExec, State: StateDisabled},
		{Property: PropProcEnum, State: StateDisabled},
		{Property: PropProcSignal, State: StateDisabled},
		{Property: PropTaskLimit, State: StateDisabled},
		{Property: PropSyscall, State: StateDisabled},
		{Property: PropLandlock, State: StateDisabled},
		{Property: PropFDTable, State: StateDisabled},
	}
	return Report{Platform: platform, Mode: mode, Results: results}
}
