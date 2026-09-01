package sandbox

import (
	"encoding/json"
	"fmt"
	"net"

	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/controlproto"
	devcontainersprofile "github.com/ejpir/gantry/internal/sandbox/devcontainers"
)

// configureSandbox applies SSH immediately when possible and persists VM
// allocation or Dev Containers topology changes for the next boot. The IDE
// image is a second block-backed OCI root and therefore cannot be toggled on a
// running VM without a restart.
func (d *daemonRuntime) configureSandbox(request controlproto.ConfigureRequest) (bool, error) {
	d.configureMu.Lock()
	defer d.configureMu.Unlock()

	update := request.SandboxUpdate()
	if request.DevContainers != nil && *request.DevContainers {
		before := d.store.Snapshot()
		if !before.DevContainers {
			candidate := before
			if err := config.ApplySandboxUpdate(&candidate, update); err != nil {
				return false, err
			}
			prepared, _, warnings, err := prepareDevContainersProfile(d.name, candidate, nil)
			if err != nil {
				return false, fmt.Errorf("enable Dev Containers: %w", err)
			}
			for _, warning := range warnings {
				d.broker.auditf("devcontainers: %s", warning)
			}
			update.DevContainersProfile = devcontainersprofile.ProfileUpdate(prepared)
		}
	}

	restartRequired := false
	_, _, err := d.store.ConfigureTransaction(update, func(before, after config.RunConfig) error {
		restartRequired = before.MemMB != after.MemMB || before.VCPUs != after.VCPUs ||
			before.ProcessIsolation != after.ProcessIsolation || before.DevContainers != after.DevContainers
		changed := restartRequired || before.SSH != after.SSH || before.DevContainers != after.DevContainers ||
			before.Runtime != after.Runtime
		if !changed {
			return nil
		}

		if after.SSH && !before.SSH {
			// d.cfg describes the roots attached to this running VM. A newly
			// enabled Dev Containers setting applies only after restart, so helper
			// delivery still targets the currently active root.
			activeTarget := guestToolsTarget{ide: d.cfg.DevContainers, label: "workload"}
			if activeTarget.ide {
				activeTarget.label = "IDE"
			}
			if !d.ensureGuestToolsTargetsAndSignal(after, []guestToolsTarget{activeTarget}) {
				return fmt.Errorf("SSH requires verified guest tools")
			}
			if err := d.startSSHGateway(); err != nil {
				return err
			}
		}
		if before.SSH && !after.SSH {
			d.stopSSHGateway()
		}
		if before.DevContainers != after.DevContainers {
			d.broker.auditf("devcontainers: IDE container enabled=%t after restart", after.DevContainers)
		}
		return nil
	})
	if err != nil {
		return false, err
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
