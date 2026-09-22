package manager

import (
	"encoding/json"
	"net/http"
	"testing"

	dashboardapi "github.com/ejpir/gantry/internal/dashboard/api"
	"github.com/ejpir/gantry/internal/packetcapture"
)

type dashboardEndpointService struct {
	dashboardapi.Service
	snapshot   dashboardapi.Snapshot
	configured *dashboardapi.SandboxConfigRequest
	captured   *packetcapture.Request
}

func (service *dashboardEndpointService) Snapshot() (dashboardapi.Snapshot, error) {
	return service.snapshot, nil
}
func (*dashboardEndpointService) ResourceLimits() dashboardapi.ResourceLimits {
	return dashboardapi.ResourceLimits{MinMemoryMB: 128, MaxMemoryMB: 4096, MaxVCPUs: 8}
}
func (*dashboardEndpointService) KernelChoices() []string { return []string{"kernel-a"} }
func (service *dashboardEndpointService) ConfigureSandbox(request dashboardapi.SandboxConfigRequest) (bool, error) {
	service.configured = &request
	return true, nil
}
func (service *dashboardEndpointService) CapturePackets(_ string, request packetcapture.Request) (packetcapture.Snapshot, error) {
	service.captured = &request
	return packetcapture.Snapshot{Active: true, Next: 7}, nil
}

type dashboardEndpointLifecycle struct {
	stubLifecycle
	service dashboardapi.Service
}

func (lifecycle dashboardEndpointLifecycle) DashboardService() dashboardapi.Service {
	return lifecycle.service
}

func TestManagerDashboardSnapshotActionsAndPackets(t *testing.T) {
	dashboard := &dashboardEndpointService{snapshot: dashboardapi.Snapshot{
		Sandboxes: []dashboardapi.Sandbox{{Name: "dev", State: dashboardapi.Running, Net: true}},
		Traffic:   []dashboardapi.Traffic{{Sandbox: "dev", Host: "example.test", Allowed: true}},
	}}
	service := newManagerService(dashboardEndpointLifecycle{service: dashboard})

	response := managerRequest(t, service, http.MethodGet, "/v1/dashboard", "", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("snapshot status=%d body=%s", response.Code, response.Body.String())
	}
	var host dashboardapi.HostSnapshot
	if err := json.Unmarshal(response.Body.Bytes(), &host); err != nil {
		t.Fatal(err)
	}
	if len(host.Snapshot.Sandboxes) != 1 || len(host.Snapshot.Traffic) != 1 || host.ResourceLimits.MaxVCPUs != 8 || len(host.KernelChoices) != 1 {
		t.Fatalf("dashboard snapshot = %+v", host)
	}

	request := dashboardapi.SandboxConfigRequest{Name: "dev", SSH: true, MemMB: 768, VCPUs: 2, ProcessIsolation: "required"}
	body, err := json.Marshal(dashboardapi.ActionRequest{Action: "configure-sandbox", SandboxConfig: &request})
	if err != nil {
		t.Fatal(err)
	}
	response = managerRequest(t, service, http.MethodPost, "/v1/dashboard/actions", string(body), nil)
	if response.Code != http.StatusOK || dashboard.configured == nil || dashboard.configured.Name != "dev" || !dashboard.configured.SSH {
		t.Fatalf("configure status=%d body=%s request=%+v", response.Code, response.Body.String(), dashboard.configured)
	}
	var result dashboardapi.ActionResult
	if json.Unmarshal(response.Body.Bytes(), &result) != nil || !result.RestartRequired {
		t.Fatalf("configure result = %s", response.Body.String())
	}

	response = managerRequest(t, service, http.MethodPost, "/v1/dashboard/packets/dev", `{"start":true,"after":3}`, nil)
	if response.Code != http.StatusOK || dashboard.captured == nil || !dashboard.captured.Start || dashboard.captured.After != 3 {
		t.Fatalf("capture status=%d body=%s request=%+v", response.Code, response.Body.String(), dashboard.captured)
	}
	var packets packetcapture.Snapshot
	if json.Unmarshal(response.Body.Bytes(), &packets) != nil || !packets.Active || packets.Next != 7 {
		t.Fatalf("packet result = %s", response.Body.String())
	}
}

func TestManagerDashboardRequiresCapability(t *testing.T) {
	service := newManagerService(stubLifecycle{})
	for _, request := range []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodGet, "/v1/dashboard", ""},
		{http.MethodPost, "/v1/dashboard/actions", `{"action":"prune-images"}`},
		{http.MethodPost, "/v1/dashboard/packets/dev", `{}`},
	} {
		response := managerRequest(t, service, request.method, request.path, request.body, nil)
		if response.Code != http.StatusNotImplemented {
			t.Fatalf("%s %s status=%d body=%s", request.method, request.path, response.Code, response.Body.String())
		}
	}
}
