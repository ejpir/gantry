package networker

import (
	"github.com/ejpir/gantry/internal/sandbox/worker"
	"github.com/ejpir/gantry/internal/workerproto"
)

// spawnNetWorkerProcess re-executes this binary in the hidden _net-worker
// role. The generic launch harness owns the exact channel table, diagnostics,
// environment, platform confinement, and process lifecycle.
func spawnNetWorkerProcess(stderrPath, confinement string) (*worker.Child, error) {
	return worker.Launch(worker.LaunchSpec{
		Role:           workerproto.RoleNet,
		EntryPoint:     "_net-worker",
		Environment:    workerEnv(),
		Channels:       []string{"control", "data"},
		DiagnosticPath: stderrPath,
		Confinement:    confinement,
	})
}
