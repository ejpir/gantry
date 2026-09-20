package manager

import (
	"errors"
	"net/http"

	dashboardapi "github.com/ejpir/gantry/internal/dashboard/api"
	"github.com/ejpir/gantry/internal/packetcapture"
	"github.com/ejpir/gantry/internal/sandbox/layout"
)

// dashboardServiceProvider is implemented by the ordinary Gantry lifecycle.
// Keeping the dashboard surface optional preserves small embedded manager
// backends while allowing a remote TUI to use the same validated control
// plane as a local TUI.
type dashboardServiceProvider interface {
	DashboardService() dashboardapi.Service
}

func (m *managerService) dashboardService(w http.ResponseWriter) (dashboardapi.Service, bool) {
	provider, ok := m.lifecycle.(dashboardServiceProvider)
	if !ok || provider.DashboardService() == nil {
		writeManagerError(w, http.StatusNotImplemented, errors.New("dashboard service unavailable"), "")
		return nil, false
	}
	return provider.DashboardService(), true
}

func (m *managerService) handleDashboardSnapshot(w http.ResponseWriter, _ *http.Request) {
	service, ok := m.dashboardService(w)
	if !ok {
		return
	}
	snapshot, err := service.Snapshot()
	if err != nil {
		writeManagerError(w, http.StatusInternalServerError, err, "")
		return
	}
	writeManagerJSON(w, http.StatusOK, dashboardapi.HostSnapshot{
		Snapshot: snapshot, ResourceLimits: service.ResourceLimits(), KernelChoices: service.KernelChoices(),
	})
}

func (m *managerService) handleDashboardAction(w http.ResponseWriter, r *http.Request) {
	service, ok := m.dashboardService(w)
	if !ok {
		return
	}
	var request dashboardapi.ActionRequest
	if _, err := decodeManagerJSON(r, &request); err != nil {
		writeManagerError(w, http.StatusBadRequest, err, "")
		return
	}
	if !tryAcquireSlot(m.execSlots) {
		writeManagerError(w, http.StatusServiceUnavailable, errors.New("too many concurrent dashboard actions"), "")
		return
	}
	defer releaseSlot(m.execSlots)
	m.organizationPolicyMu.RLock()
	defer m.organizationPolicyMu.RUnlock()
	if name := dashboardActionSandbox(request); layout.ValidName(name) {
		lock := m.sandboxLock(name)
		lock.Lock()
		defer lock.Unlock()
	}
	result, err := runDashboardAction(service, request)
	if err != nil {
		writeManagerError(w, http.StatusBadRequest, err, "")
		return
	}
	writeManagerJSON(w, http.StatusOK, result)
}

func dashboardActionSandbox(request dashboardapi.ActionRequest) string {
	switch {
	case request.SandboxConfig != nil:
		return request.SandboxConfig.Name
	case request.RuleRequest != nil:
		return request.RuleRequest.Sandbox
	case request.Rule != nil:
		return request.Rule.Sandbox
	case request.Traffic != nil:
		return request.Traffic.Sandbox
	case request.Secret != nil:
		return request.Secret.Sandbox
	case request.SecretRow != nil:
		return request.SecretRow.Sandbox
	case request.MCPRemote != nil:
		return request.MCPRemote.Sandbox
	case request.MCPFilesystem != nil:
		return request.MCPFilesystem.Sandbox
	case request.MCPServer != nil:
		return request.MCPServer.Sandbox
	case request.Share != nil:
		return request.Share.Sandbox
	case request.SharePlan != nil:
		return request.SharePlan.Sandbox
	case request.Mount != nil:
		return request.Mount.Sandbox
	case request.Port != nil:
		return request.Port.Sandbox
	}
	return ""
}

func runDashboardAction(service dashboardapi.Service, request dashboardapi.ActionRequest) (dashboardapi.ActionResult, error) {
	missing := func(name string) (dashboardapi.ActionResult, error) {
		return dashboardapi.ActionResult{}, errors.New("dashboard action " + request.Action + " requires " + name)
	}
	switch request.Action {
	case "validate-sandbox-config":
		if request.SandboxConfig == nil {
			return missing("sandboxConfig")
		}
		return dashboardapi.ActionResult{}, service.ValidateSandboxConfig(*request.SandboxConfig)
	case "configure-sandbox":
		if request.SandboxConfig == nil {
			return missing("sandboxConfig")
		}
		restart, err := service.ConfigureSandbox(*request.SandboxConfig)
		return dashboardapi.ActionResult{RestartRequired: restart}, err
	case "validate-rule":
		if request.RuleRequest == nil {
			return missing("ruleRequest")
		}
		return dashboardapi.ActionResult{}, service.ValidateNetworkRule(*request.RuleRequest)
	case "add-rule":
		if request.RuleRequest == nil {
			return missing("ruleRequest")
		}
		return dashboardapi.ActionResult{}, service.AddNetworkRule(*request.RuleRequest)
	case "remove-rule":
		if request.Rule == nil {
			return missing("rule")
		}
		return dashboardapi.ActionResult{}, service.RemoveNetworkRule(*request.Rule)
	case "remove-traffic-rule":
		if request.Traffic == nil {
			return missing("traffic")
		}
		return dashboardapi.ActionResult{}, service.RemoveTrafficRule(*request.Traffic)
	case "validate-secret":
		if request.Secret == nil {
			return missing("secret")
		}
		return dashboardapi.ActionResult{}, service.ValidateSecret(*request.Secret)
	case "add-secret":
		if request.Secret == nil {
			return missing("secret")
		}
		return dashboardapi.ActionResult{}, service.AddSecret(*request.Secret)
	case "remove-secret":
		if request.SecretRow == nil {
			return missing("secretRow")
		}
		return dashboardapi.ActionResult{}, service.RemoveSecret(*request.SecretRow)
	case "validate-mcp-remote":
		if request.MCPRemote == nil {
			return missing("mcpRemote")
		}
		return dashboardapi.ActionResult{}, service.ValidateMCPRemote(*request.MCPRemote)
	case "configure-mcp-remote":
		if request.MCPRemote == nil {
			return missing("mcpRemote")
		}
		return dashboardapi.ActionResult{}, service.ConfigureMCPRemote(*request.MCPRemote)
	case "validate-mcp-filesystem":
		if request.MCPFilesystem == nil {
			return missing("mcpFilesystem")
		}
		return dashboardapi.ActionResult{}, service.ValidateMCPFilesystem(*request.MCPFilesystem)
	case "configure-mcp-filesystem":
		if request.MCPFilesystem == nil {
			return missing("mcpFilesystem")
		}
		return dashboardapi.ActionResult{}, service.ConfigureMCPFilesystem(*request.MCPFilesystem)
	case "remove-mcp-remote":
		if request.MCPServer == nil {
			return missing("mcpServer")
		}
		return dashboardapi.ActionResult{}, service.RemoveMCPRemote(*request.MCPServer)
	case "remove-image":
		return dashboardapi.ActionResult{}, service.RemoveImage(request.Value)
	case "prune-images":
		count, err := service.PruneImages()
		return dashboardapi.ActionResult{Count: count}, err
	case "validate-registry":
		if request.Registry == nil {
			return missing("registry")
		}
		return dashboardapi.ActionResult{}, service.ValidateRegistryLogin(*request.Registry)
	case "store-registry":
		if request.Registry == nil {
			return missing("registry")
		}
		warning, err := service.StoreRegistryLogin(*request.Registry)
		return dashboardapi.ActionResult{Warning: warning}, err
	case "remove-registry":
		return dashboardapi.ActionResult{}, service.RemoveRegistryLogin(request.Value)
	case "plan-share":
		if request.Share == nil {
			return missing("share")
		}
		plan, err := service.PlanShare(*request.Share)
		return dashboardapi.ActionResult{SharePlan: &plan}, err
	case "configure-share":
		if request.SharePlan == nil {
			return missing("sharePlan")
		}
		return dashboardapi.ActionResult{}, service.ConfigureShare(*request.SharePlan)
	case "remove-share":
		if request.Mount == nil {
			return missing("mount")
		}
		return dashboardapi.ActionResult{}, service.RemoveShare(*request.Mount)
	case "plan-port":
		if request.PortRequest == nil {
			return missing("portRequest")
		}
		spec, err := service.PlanPort(*request.PortRequest)
		return dashboardapi.ActionResult{PortSpec: spec}, err
	case "publish-port":
		if request.Port == nil {
			return missing("port")
		}
		return dashboardapi.ActionResult{}, service.PublishPort(request.Port.Sandbox, request.Port.Spec)
	case "unpublish-port":
		if request.Port == nil {
			return missing("port")
		}
		return dashboardapi.ActionResult{}, service.UnpublishPort(request.Port.Sandbox, request.Port.Spec)
	default:
		return dashboardapi.ActionResult{}, errors.New("unknown dashboard action " + request.Action)
	}
}

func (m *managerService) handleDashboardPackets(w http.ResponseWriter, r *http.Request) {
	name, ok := managerSandboxName(w, r)
	if !ok {
		return
	}
	service, ok := m.dashboardService(w)
	if !ok {
		return
	}
	m.organizationPolicyMu.RLock()
	defer m.organizationPolicyMu.RUnlock()
	lock := m.sandboxLock(name)
	lock.RLock()
	defer lock.RUnlock()
	var request packetcapture.Request
	if _, err := decodeManagerJSON(r, &request); err != nil {
		writeManagerError(w, http.StatusBadRequest, err, "")
		return
	}
	snapshot, err := service.CapturePackets(name, request)
	if err != nil {
		writeManagerError(w, http.StatusBadRequest, err, "")
		return
	}
	writeManagerJSON(w, http.StatusOK, snapshot)
}
