package manager

import (
	"encoding/json"
	"github.com/ejpir/gantry/api/managerapi"
	dashboardapi "github.com/ejpir/gantry/internal/dashboard/api"
	"net/http"
	"strings"
	"testing"
)

func TestDashboardRejectsAmbiguousPayloadsBeforeSelectingLockOrCallingService(t *testing.T) {
	for _, body := range []string{
		`{"action":"configure-sandbox","sandboxConfig":{"Name":"dev"},"rule":{"Sandbox":"other"}}`,
		`{"action":"configure-sandbox","sandboxConfig":{"Name":"dev"},"rule":null}`,
		`{"action":"configure-sandbox","sandboxConfig":null}`,
		`{"action":"prune-images","value":""}`,
		`{"action":"remove-rule","rule":{"Sandbox":"dev","Remote":"other-host"}}`,
		`{"action":"unknown-sensitive-action"}`,
	} {
		dashboard := &dashboardEndpointService{}
		service := newManagerService(dashboardEndpointLifecycle{service: dashboard})
		response := managerRequest(t, service, http.MethodPost, "/v1/dashboard/actions", body, nil)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("status=%d for %s", response.Code, body)
		}
		if dashboard.configured != nil {
			t.Fatal("invalid action reached the service")
		}
	}
}
func TestEveryDashboardActionHasOneDocumentedPayload(t *testing.T) {
	for _, action := range dashboardapi.ActionNames() {
		request := map[string]any{"action": action}
		payload := dashboardapi.ActionPayload(action)
		if payload == "value" {
			request[payload] = "example"
		} else if payload != "" {
			request[payload] = map[string]any{}
		}
		body, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		var decoded dashboardapi.ActionRequest
		if err := json.Unmarshal(body, &decoded); err != nil {
			t.Fatal(err)
		}
		if err := decoded.ValidateJSON(body); err != nil {
			t.Fatalf("%s: %v", action, err)
		}
		if !strings.Contains(string(managerapi.OpenAPI), action) {
			t.Fatalf("action %s missing from schema", action)
		}
	}
}
