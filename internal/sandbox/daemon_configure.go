package sandbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"

	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/controlproto"
)

func sandboxUpdate(request controlproto.ConfigureRequest) config.SandboxUpdate {
	return config.SandboxUpdate{
		SSH: request.SSH, DevContainers: request.DevContainers,
		MemMB: request.MemMB, VCPUs: request.VCPUs,
		ProcessIsolation: request.ProcessIsolation,
	}
}

// configureSandbox applies SSH immediately when possible and persists VM
// allocation or Dev Containers topology changes for the next boot. The IDE
// image is a second block-backed OCI root and therefore cannot be toggled on a
// running VM without a restart.
func (d *daemonRuntime) configureSandbox(request controlproto.ConfigureRequest) (bool, error) {
	d.configureMu.Lock()
	defer d.configureMu.Unlock()

	before := d.store.Snapshot()
	after := before
	if err := config.ApplySandboxUpdate(&after, sandboxUpdate(request)); err != nil {
		return false, err
	}
	restartRequired := before.MemMB != after.MemMB || before.VCPUs != after.VCPUs ||
		before.ProcessIsolation != after.ProcessIsolation || before.DevContainers != after.DevContainers
	changed := restartRequired || before.SSH != after.SSH || before.DevContainers != after.DevContainers ||
		before.Runtime != after.Runtime
	if !changed {
		return false, nil
	}

	if err := d.store.Configure(sandboxUpdate(request)); err != nil {
		return false, err
	}
	rollback := func(cause error) error {
		err := d.store.Mutate(func(current *config.RunConfig) error {
			// Do not erase an independent resource update that completed while
			// guest tools were being delivered. Revert only requested fields
			// whose value still matches this configure operation.
			if request.SSH != nil && current.SSH == after.SSH {
				current.SSH = before.SSH
			}
			if request.DevContainers != nil && current.DevContainers == after.DevContainers {
				current.DevContainers = before.DevContainers
				if current.DevContainersDiskMiB == after.DevContainersDiskMiB {
					current.DevContainersDiskMiB = before.DevContainersDiskMiB
				}
			}
			if request.MemMB != nil && current.MemMB == after.MemMB {
				current.MemMB = before.MemMB
			}
			if request.VCPUs != nil && current.VCPUs == after.VCPUs {
				current.VCPUs = before.VCPUs
			}
			if request.ProcessIsolation != nil && current.ProcessIsolation == after.ProcessIsolation {
				current.ProcessIsolation = before.ProcessIsolation
			}
			if err := config.ValidateSandboxResources(current.MemMB, current.VCPUs); err != nil {
				return err
			}
			if err := config.ValidateProcessIsolation(current.ProcessIsolation); err != nil {
				return err
			}
			return config.ValidateDevContainers(*current)
		})
		if err != nil {
			return errors.Join(cause, fmt.Errorf("roll back sandbox configuration: %w", err))
		}
		return cause
	}

	if after.SSH && !before.SSH {
		activeTarget := guestToolsTarget{ide: d.cfg.DevContainers, label: "workload"}
		if activeTarget.ide {
			activeTarget.label = "IDE"
		}
		if !d.ensureGuestToolsTargetsAndSignal(after, []guestToolsTarget{activeTarget}) {
			return false, rollback(fmt.Errorf("SSH requires verified guest tools"))
		}
		if err := d.startSSHGateway(); err != nil {
			return false, rollback(err)
		}
	}
	if before.SSH && !after.SSH {
		d.stopSSHGateway()
	}
	if before.DevContainers != after.DevContainers {
		d.broker.auditf("devcontainers: IDE container enabled=%t after restart", after.DevContainers)
	}
	return restartRequired, nil
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
