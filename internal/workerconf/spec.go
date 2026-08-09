// Package workerconf confines a re-executed worker process after it has
// consumed its descriptor table and before it opens the hypervisor.
// See docs/worker-confinement.md: one platform-neutral contract (Spec),
// per-platform enforcers (Apply), and one shared in-worker verifier
// (Verify) so isolation.json reports VERIFIED properties rather than
// platform claims.
package workerconf

// Spec is the worker's declared ambient-authority requirement. One
// definition, consumed by every platform enforcer.
type Spec struct {
	NoNetwork  bool // no inbound/outbound sockets ever
	NoExec     bool // no exec/spawn of any program
	NoNewPaths bool // no open-by-path after Apply (empty private root on linux)
	NoProcX    bool // no cross-process ptrace/signal/enumeration
	KeepFDs    int  // descriptors 0..KeepFDs survive Apply (the fd table is dense)
	// KeepFDExtra lists additional LIVE descriptors that must survive
	// the close tier: the net.FileConn dups of the inherited channel
	// conns land ABOVE the dense table (a dup takes the first free fd),
	// and closing them severs the control/data channels mid-boot
	// (AL2023 field failure: close_range killed the control dup, the
	// supervisor EOF'd and SIGKILLed the healthy worker).
	KeepFDExtra []int
	ConfRoot    string // linux: supervisor-created mountpoint for the private root

	// WriteFiles lists the pre-opened log files whose writes Seatbelt
	// path-checks on every operation. They are LITERAL paths, never
	// directory subtrees: the logs' parent directory also holds trusted
	// state (sandbox.json — shares, ports, net policy), so a subpath
	// grant there would let a compromised worker rewrite the sandbox
	// configuration a later resume trusts.
	WriteFiles []string

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
		NoNetwork:  true,
		NoExec:     true,
		NoNewPaths: true,
		NoProcX:    true,
		KeepFDs:    keepFDs,
		ConfRoot:   confRoot,
	}
}

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
	}
	return Report{Platform: platform, Mode: mode, Results: results}
}
