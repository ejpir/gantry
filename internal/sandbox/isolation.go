package sandbox

import (
	"encoding/json"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/ejpir/gantry/internal/atomicfile"
	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/workerconf"
)

// isolationState is the machine-readable effective isolation of a running
// sandbox (dir/isolation.json, 0600). It reports only successfully installed
// controls; requested configuration is never treated as proof of enforcement.
type isolationState struct {
	Version            int                `json:"version"`
	Topology           string             `json:"topology"`
	Platform           string             `json:"platform"`
	NetworkBoundary    string             `json:"networkBoundary"`
	FilesystemBoundary string             `json:"filesystemBoundary"`
	ProcessBoundary    string             `json:"processBoundary"`
	Degraded           []string           `json:"degraded"`
	NetworkConfinement *workerconf.Report `json:"networkConfinement,omitempty"`
	VMMConfinement     *workerconf.Report `json:"vmmConfinement,omitempty"`
	MCPConfinement     *workerconf.Report `json:"mcpConfinement,omitempty"`
	MCPBoundary        *mcpBoundaryState  `json:"mcpBoundary,omitempty"`
}

// mcpBoundaryState records supervisor-established topology properties. These
// are protocol facts, not inferred from an in-worker negative probe.
type mcpBoundaryState struct {
	ProcessSplit       bool `json:"processSplit"`
	OpaqueStreamRelay  bool `json:"opaqueStreamRelay"`
	OriginDialBrokered bool `json:"originDialBrokered"`
	LocalExecBrokered  bool `json:"localExecBrokered"`
	CredentialScoped   bool `json:"credentialScoped"`
}

// writeIsolationState persists the effective runtime topology and the VMM
// worker's verified confinement report for CLI and dashboard consumers.
func writeIsolationState(dir string, cfg config.RunConfig, network *Network, splitVMM bool,
	confinement, mcpConfinement *workerconf.Report) error {
	state := isolationState{
		Version:            3,
		Topology:           "monolithic",
		Platform:           runtime.GOOS,
		NetworkBoundary:    workerconf.StateUnavailable,
		FilesystemBoundary: workerconf.StateUnavailable,
		ProcessBoundary:    workerconf.StateUnavailable,
	}
	degraded := append([]string(nil), network.Degraded...)
	if network.Split {
		state.NetworkConfinement = network.Confinement
	}
	if splitVMM {
		state.VMMConfinement = confinement
	}
	if cfg.MCP && mcpConfinement != nil {
		state.MCPConfinement = mcpConfinement
		state.MCPBoundary = &mcpBoundaryState{
			ProcessSplit: true, OpaqueStreamRelay: true, OriginDialBrokered: true,
			LocalExecBrokered: true, CredentialScoped: true,
		}
	}
	// The network worker intentionally owns socket authority. This boundary
	// aggregates roles that must not be able to create ambient connections.
	state.NetworkBoundary = aggregateRoleBoundary(
		propertyState(state.VMMConfinement, workerconf.PropNetDial),
		propertyState(state.MCPConfinement, workerconf.PropNetDial),
	)
	state.FilesystemBoundary = aggregateRoleBoundary(
		roleFilesystemBoundary(state.NetworkConfinement),
		roleFilesystemBoundary(state.VMMConfinement),
		roleFilesystemBoundary(state.MCPConfinement),
	)
	state.ProcessBoundary = aggregateRoleBoundary(
		roleProcessBoundary(state.NetworkConfinement),
		roleProcessBoundary(state.VMMConfinement),
		roleProcessBoundary(state.MCPConfinement),
	)

	if cfg.ProcessIsolation == "off" {
		degraded = append(degraded, "process isolation disabled by configuration")
	} else {
		var splitRoles []string
		if network.Split {
			splitRoles = append(splitRoles, "split-net")
		}
		if splitVMM {
			splitRoles = append(splitRoles, "split-vmm")
		}
		if cfg.MCP && mcpConfinement != nil {
			splitRoles = append(splitRoles, "split-mcp")
		}
		if len(splitRoles) != 0 {
			state.Topology = strings.Join(splitRoles, "+")
		}
		if network.Split {
			degraded = appendConfinementDegradations(degraded, "network", network.Confinement)
		}
		if splitVMM {
			degraded = appendConfinementDegradations(degraded, "vmm", confinement)
		}
		if cfg.MCP {
			degraded = appendConfinementDegradations(degraded, "mcp", mcpConfinement)
		}
		if !network.Split && cfg.Net && cfg.GVProxy == "" {
			degraded = append(degraded, "network worker not established")
		}
		if !splitVMM && config.NormalizeProcessIsolation(cfg.ProcessIsolation) != "off" {
			degraded = append(degraded, "vmm worker not established")
		}
	}
	state.Degraded = degraded

	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.WriteFile(filepath.Join(dir, "isolation.json"), append(raw, '\n'), 0o600)
}

func appendConfinementDegradations(degraded []string, role string, confinement *workerconf.Report) []string {
	switch {
	case confinement == nil:
		return append(degraded, role+" worker confinement report unavailable")
	case !confinement.Applied:
		return append(degraded, role+" worker confinement not applied: "+strings.Join(confinement.Notes, "; "))
	default:
		for _, result := range confinement.Results {
			if result.State != workerconf.StateEnforced && result.State != workerconf.StateDisabled {
				degraded = append(degraded, role+" worker confinement: "+result.Property+" "+result.State)
			}
		}
		return degraded
	}
}

func propertyState(report *workerconf.Report, property string) string {
	if report == nil {
		return ""
	}
	return report.Property(property).State
}

func roleFilesystemBoundary(report *workerconf.Report) string {
	if report == nil {
		return ""
	}
	states := []string{
		report.Property(workerconf.PropFSRead).State,
		report.Property(workerconf.PropFSWrite).State,
	}
	if report.Platform == "linux" {
		// A leaked inherited file descriptor bypasses every path-open policy;
		// Linux therefore claims an enforced filesystem boundary only when the
		// worker also proved its descriptor table contains justified entries.
		states = append(states, report.Property(workerconf.PropFDTable).State)
		if report.Property(workerconf.PropLandlock).State != workerconf.StateUnavailable {
			states = append(states, report.Property(workerconf.PropLandlock).State)
		}
	}
	return aggregateRoleBoundary(states...)
}

func roleProcessBoundary(report *workerconf.Report) string {
	if report == nil {
		return ""
	}
	properties := []string{workerconf.PropExec}
	switch report.Platform {
	case "linux":
		properties = append(properties, workerconf.PropSyscall, workerconf.PropProcEnum, workerconf.PropTaskLimit)
	case "darwin":
		properties = append(properties, workerconf.PropProcEnum, workerconf.PropProcSignal)
	}
	states := make([]string, 0, len(properties))
	for _, property := range properties {
		states = append(states, report.Property(property).State)
	}
	return aggregateRoleBoundary(states...)
}

// aggregateRoleBoundary returns enforced only when every present role/property
// is enforced. Empty inputs mean no applicable worker report. The ordering
// favors definite counter-evidence over uncertainty for operator visibility.
func aggregateRoleBoundary(states ...string) string {
	seen := false
	worst := workerconf.StateEnforced
	for _, state := range states {
		if state == "" {
			continue
		}
		seen = true
		if boundaryRank(state) > boundaryRank(worst) {
			worst = state
		}
	}
	if !seen {
		return workerconf.StateUnavailable
	}
	return worst
}

func boundaryRank(state string) int {
	switch state {
	case workerconf.StateEnforced:
		return 0
	case workerconf.StateDisabled:
		return 1
	case workerconf.StateUnavailable:
		return 2
	case workerconf.StateIndeterminate:
		return 3
	case workerconf.StateUnenforced:
		return 4
	default:
		return 3
	}
}
