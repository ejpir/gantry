package sandbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"

	"github.com/ejpir/gantry/internal/atomicfile"
	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/controlproto"
	devcontainersprofile "github.com/ejpir/gantry/internal/sandbox/devcontainers"
)

// configureSandbox prepares and commits one revisioned desired configuration,
// then explicitly reconciles host services to it. VM allocation and Dev
// Containers topology remain restart-only; the SSH endpoint converges live.
func (d *daemonRuntime) configureSandbox(request controlproto.ConfigureRequest) (bool, error) {
	tx, err := d.store.BeginConfiguration(request.SandboxUpdate())
	if err != nil {
		return false, err
	}
	defer tx.Close()

	before := tx.Before()
	if request.DevContainers != nil && *request.DevContainers && !before.DevContainers {
		prepared, _, warnings, err := prepareDevContainersProfile(d.name, tx.Desired(), nil)
		if err != nil {
			return false, fmt.Errorf("enable Dev Containers: %w", err)
		}
		for _, warning := range warnings {
			d.broker.auditf("devcontainers: %s", warning)
		}
		if err := tx.Amend(config.SandboxUpdate{
			DevContainersProfile: devcontainersprofile.ProfileUpdate(prepared),
		}); err != nil {
			return false, err
		}
	}

	desired := tx.Desired()
	restartRequired := before.MemMB != desired.MemMB || before.VCPUs != desired.VCPUs ||
		before.ProcessIsolation != desired.ProcessIsolation || before.DevContainers != desired.DevContainers
	persistErr := tx.Commit()
	if persistErr != nil && !atomicfile.Committed(persistErr) {
		return false, persistErr
	}
	after := tx.After()
	if reconcileErr := d.reconcileSandboxServices(after); reconcileErr != nil {
		if !tx.Changed() {
			return false, reconcileErr
		}
		rollbackErr := tx.Rollback()
		result := reconcileErr
		// A committed warning from the desired write describes a transient
		// revision after a successful rollback, so retain it as diagnostic text
		// without marking the final error as owning that commit point.
		if persistErr != nil {
			result = errors.Join(result, fmt.Errorf("configuration durability was uncertain before service rollback: %v", persistErr))
		}
		if rollbackErr != nil {
			result = errors.Join(result, fmt.Errorf("roll back sandbox settings: %w", rollbackErr))
		}
		// Whether rollback committed, conflicted, or failed before replacement,
		// the store snapshot is the authoritative desired state. Reconcile it so
		// a concurrent newer revision is never left behind in live services.
		if restoreErr := d.reconcileSandboxServices(d.store.Snapshot()); restoreErr != nil {
			result = errors.Join(result, fmt.Errorf("reconcile authoritative sandbox services: %w", restoreErr))
		}
		return false, result
	}
	if before.DevContainers != after.DevContainers {
		d.broker.auditf("devcontainers: IDE container enabled=%t after restart", after.DevContainers)
	}
	return restartRequired, persistErr
}

// reconcileSandboxServices converges actual host-owned services to desired
// persisted state. It intentionally observes service state rather than
// inferring it from the previous configuration, making retries and no-op
// configure requests repair partial service failures.
func (d *daemonRuntime) reconcileSandboxServices(desired config.RunConfig) error {
	d.sshMu.Lock()
	sshRunning := d.sshListener != nil
	d.sshMu.Unlock()
	if desired.SSH == sshRunning {
		return nil
	}
	if !desired.SSH {
		d.stopSSHGateway()
		return nil
	}

	// d.cfg describes the roots attached to this running VM. A newly enabled
	// Dev Containers setting applies only after restart, so helper delivery
	// still targets the currently active root.
	activeTarget := guestToolsTarget{ide: d.cfg.DevContainers, label: "workload"}
	if activeTarget.ide {
		activeTarget.label = "IDE"
	}
	if !d.ensureGuestToolsTargetsAndSignal(desired, []guestToolsTarget{activeTarget}) {
		return fmt.Errorf("SSH requires verified guest tools")
	}
	return d.startSSHGateway()
}

func (br *broker) configureControl(connection net.Conn, request controlproto.Request) {
	respond := func(response controlproto.ConfigureResponse) {
		_ = json.NewEncoder(connection).Encode(&response)
	}
	if request.Configure == nil || br.configure == nil {
		respond(controlproto.ConfigureResponse{Error: "sandbox configuration unavailable"})
		return
	}
	restartRequired, err := br.configure(*request.Configure)
	if err != nil {
		respond(controlproto.ConfigureResponse{Error: err.Error()})
		return
	}
	respond(controlproto.ConfigureResponse{OK: true, RestartRequired: restartRequired})
}
