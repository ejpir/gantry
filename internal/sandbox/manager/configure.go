package manager

import (
	"net/http"

	"github.com/ejpir/gantry/api/managerapi"
	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/controlcmd"
	"github.com/ejpir/gantry/internal/sandbox/controlproto"
	"github.com/ejpir/gantry/internal/sandbox/layout"
)

func (m *managerService) handleConfigureSandbox(w http.ResponseWriter, r *http.Request) {
	name, ok := managerSandboxName(w, r)
	if !ok {
		return
	}
	var request managerapi.ConfigureSandboxRequest
	body, err := decodeManagerJSON(r, &request)
	local := controlproto.ConfigureRequest{SSH: request.SSH, DevContainers: request.DevContainers,
		MemMB: request.MemoryMiB, VCPUs: request.CPUs, ProcessIsolation: request.ProcessIsolation}
	if err == nil {
		err = controlcmd.ValidateConfigureRequest(local)
	}
	if err != nil {
		writeManagerError(w, http.StatusBadRequest, err, "")
		return
	}
	m.runLifecycle(w, r, "configure", name, body, http.StatusOK, func(owner operationOwner) error {
		// Do not manufacture a missing sandbox by taking its launch lock.
		if _, err := config.ReadSandboxConfig(layout.Dir(name)); err != nil {
			return err
		}
		restart, err := controlcmd.Configure(name, local)
		if err != nil {
			return err
		}
		return m.operationState.setConfigure(owner, managerapi.ConfigureSandboxResult{RestartRequired: restart})
	})
}
