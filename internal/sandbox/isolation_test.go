package sandbox

// isolation.json is written from the resolved network plus each worker's
// verified confinement report, so it lives with the assembly that produces it.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/workerconf"
)

func TestWriteIsolationStateConfinement(t *testing.T) {
	dir := t.TempDir()
	nw := &Network{}
	conf := &workerconf.Report{
		Platform: "linux", Mode: "auto", Applied: true,
		Results: []workerconf.PropertyResult{
			{Property: workerconf.PropFSRead, State: workerconf.StateEnforced},
			{Property: workerconf.PropNetDial, State: workerconf.StateEnforced},
			{Property: workerconf.PropExec, State: workerconf.StateEnforced},
			{Property: workerconf.PropFDTable, State: workerconf.StateEnforced},
			{Property: workerconf.PropProcEnum, State: workerconf.StateUnenforced, Detail: "/proc readable"},
			{Property: workerconf.PropTaskLimit, State: workerconf.StateEnforced},
			{Property: workerconf.PropFSWrite, State: workerconf.StateUnenforced, Detail: "probe"},
		},
	}
	if err := writeIsolationState(dir, config.RunConfig{ProcessIsolation: "auto"}, nw, true, conf, nil); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "isolation.json"))
	if err != nil {
		t.Fatal(err)
	}
	var st isolationState
	if err := json.Unmarshal(data, &st); err != nil {
		t.Fatal(err)
	}
	if st.Version != 3 || st.VMMConfinement == nil || !st.VMMConfinement.Applied || st.NetworkConfinement != nil {
		t.Fatalf("report not persisted: %s", data)
	}
	if st.FilesystemBoundary != workerconf.StateUnenforced || st.NetworkBoundary != workerconf.StateEnforced {
		t.Fatalf("boundaries not filled from report: %+v", st)
	}
	if st.ProcessBoundary != workerconf.StateUnenforced {
		t.Fatalf("Linux process boundary ignored proc-enum: %+v", st)
	}
	// The one unenforced property must surface in Degraded.
	found := false
	for _, d := range st.Degraded {
		if strings.Contains(d, workerconf.PropFSWrite) {
			found = true
		}
	}
	if !found {
		t.Fatalf("unenforced property not reported degraded: %v", st.Degraded)
	}
	// Monolithic boot: no report, honest unavailable everywhere.
	if err := writeIsolationState(dir, config.RunConfig{ProcessIsolation: "auto"}, nw, false, nil, nil); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(filepath.Join(dir, "isolation.json"))
	var st2 isolationState
	if err := json.Unmarshal(data, &st2); err != nil {
		t.Fatal(err)
	}
	if st2.VMMConfinement != nil || st2.NetworkConfinement != nil || st2.FilesystemBoundary != "unavailable" {
		t.Fatalf("monolithic state not honestly unavailable: %+v", st2)
	}
}

func TestWriteIsolationStateSeparatesWorkerRoles(t *testing.T) {
	enforced := func(networkRole bool) *workerconf.Report {
		netDial := workerconf.StateEnforced
		if networkRole {
			netDial = workerconf.StateDisabled
		}
		return &workerconf.Report{
			Platform: "linux", Mode: "required", Applied: true,
			Results: []workerconf.PropertyResult{
				{Property: workerconf.PropFSRead, State: workerconf.StateEnforced},
				{Property: workerconf.PropFSWrite, State: workerconf.StateEnforced},
				{Property: workerconf.PropNetDial, State: netDial},
				{Property: workerconf.PropExec, State: workerconf.StateEnforced},
				{Property: workerconf.PropFDTable, State: workerconf.StateEnforced},
				{Property: workerconf.PropSyscall, State: workerconf.StateEnforced},
				{Property: workerconf.PropProcEnum, State: workerconf.StateEnforced},
				{Property: workerconf.PropTaskLimit, State: workerconf.StateEnforced},
			},
		}
	}
	dir := t.TempDir()
	networkReport := enforced(true)
	vmmReport := enforced(false)
	network := &Network{Split: true, Confinement: networkReport}
	if err := writeIsolationState(dir, config.RunConfig{Net: true, ProcessIsolation: "required"}, network, true, vmmReport, nil); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "isolation.json"))
	if err != nil {
		t.Fatal(err)
	}
	var state isolationState
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatal(err)
	}
	if state.NetworkConfinement == nil || state.VMMConfinement == nil {
		t.Fatalf("role reports not persisted separately: %s", data)
	}
	if state.Topology != "split-net+split-vmm" || state.FilesystemBoundary != workerconf.StateEnforced ||
		state.ProcessBoundary != workerconf.StateEnforced || state.NetworkBoundary != workerconf.StateEnforced {
		t.Fatalf("role boundaries = %+v", state)
	}
	if len(state.Degraded) != 0 {
		t.Fatalf("fully enforced roles reported degraded: %v", state.Degraded)
	}
}

func TestWriteIsolationStateIncludesMCPWorker(t *testing.T) {
	dir := t.TempDir()
	mcp := &workerconf.Report{Platform: "linux", Mode: "required", Applied: true,
		Results: []workerconf.PropertyResult{
			{Property: workerconf.PropFSRead, State: workerconf.StateEnforced},
			{Property: workerconf.PropFSWrite, State: workerconf.StateEnforced},
			{Property: workerconf.PropNetDial, State: workerconf.StateEnforced},
			{Property: workerconf.PropExec, State: workerconf.StateEnforced},
			{Property: workerconf.PropFDTable, State: workerconf.StateEnforced},
			{Property: workerconf.PropSyscall, State: workerconf.StateEnforced},
			{Property: workerconf.PropLandlock, State: workerconf.StateEnforced},
			{Property: workerconf.PropProcEnum, State: workerconf.StateEnforced},
			{Property: workerconf.PropTaskLimit, State: workerconf.StateEnforced},
		}}
	cfg := config.RunConfig{MCP: true, ProcessIsolation: "required"}
	if err := writeIsolationState(dir, cfg, &Network{}, true, mcp, mcp); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "isolation.json"))
	if err != nil {
		t.Fatal(err)
	}
	var state isolationState
	if err := json.Unmarshal(raw, &state); err != nil {
		t.Fatal(err)
	}
	if state.Topology != "split-vmm+split-mcp" || state.MCPConfinement == nil ||
		state.MCPBoundary == nil || !state.MCPBoundary.ProcessSplit || !state.MCPBoundary.OpaqueStreamRelay ||
		!state.MCPBoundary.OriginDialBrokered || !state.MCPBoundary.LocalExecBrokered ||
		!state.MCPBoundary.CredentialScoped || state.NetworkBoundary != workerconf.StateEnforced ||
		state.FilesystemBoundary != workerconf.StateEnforced ||
		state.ProcessBoundary != workerconf.StateEnforced || len(state.Degraded) != 0 {
		t.Fatalf("MCP isolation state = %+v\n%s", state, raw)
	}
}

func TestWriteIsolationStateClassifiesLandlockAsFilesystemBoundary(t *testing.T) {
	dir := t.TempDir()
	conf := &workerconf.Report{Platform: "linux", Mode: "auto", Applied: true,
		Results: []workerconf.PropertyResult{
			{Property: workerconf.PropFSRead, State: workerconf.StateEnforced},
			{Property: workerconf.PropFSWrite, State: workerconf.StateEnforced},
			{Property: workerconf.PropNetDial, State: workerconf.StateEnforced},
			{Property: workerconf.PropExec, State: workerconf.StateEnforced},
			{Property: workerconf.PropFDTable, State: workerconf.StateEnforced},
			{Property: workerconf.PropSyscall, State: workerconf.StateEnforced},
			{Property: workerconf.PropLandlock, State: workerconf.StateUnenforced},
			{Property: workerconf.PropProcEnum, State: workerconf.StateEnforced},
			{Property: workerconf.PropTaskLimit, State: workerconf.StateEnforced},
		}}
	if err := writeIsolationState(dir, config.RunConfig{ProcessIsolation: "auto"}, &Network{}, true, conf, nil); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "isolation.json"))
	if err != nil {
		t.Fatal(err)
	}
	var state isolationState
	if err := json.Unmarshal(raw, &state); err != nil {
		t.Fatal(err)
	}
	if state.FilesystemBoundary != workerconf.StateUnenforced || state.ProcessBoundary != workerconf.StateEnforced {
		t.Fatalf("Landlock boundary classification = %+v", state)
	}
}

func TestWriteIsolationStateDarwinAggregatesSignalBoundary(t *testing.T) {
	dir := t.TempDir()
	conf := &workerconf.Report{
		Platform: "darwin", Mode: "auto", Applied: true,
		Results: []workerconf.PropertyResult{
			{Property: workerconf.PropFSRead, State: workerconf.StateEnforced},
			{Property: workerconf.PropFSWrite, State: workerconf.StateEnforced},
			{Property: workerconf.PropNetDial, State: workerconf.StateEnforced},
			{Property: workerconf.PropExec, State: workerconf.StateEnforced},
			{Property: workerconf.PropProcEnum, State: workerconf.StateUnavailable},
			{Property: workerconf.PropProcSignal, State: workerconf.StateUnenforced},
		},
	}
	if err := writeIsolationState(dir, config.RunConfig{ProcessIsolation: "auto"}, &Network{}, true, conf, nil); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "isolation.json"))
	if err != nil {
		t.Fatal(err)
	}
	var state isolationState
	if err := json.Unmarshal(raw, &state); err != nil {
		t.Fatal(err)
	}
	if state.ProcessBoundary != workerconf.StateUnenforced {
		t.Fatalf("Darwin process boundary ignored proc-signal: %+v", state)
	}
}
