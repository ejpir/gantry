package remote

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	dashboardapi "github.com/ejpir/gantry/internal/dashboard/api"
	"github.com/ejpir/gantry/internal/packetcapture"
	"github.com/ejpir/gantry/internal/secret"
)

func TestClientDashboardCalls(t *testing.T) {
	var action dashboardapi.ActionRequest
	var capture packetcapture.Request
	_, profile := stubManager(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/dashboard":
			_ = json.NewEncoder(w).Encode(dashboardapi.HostSnapshot{
				Snapshot:       dashboardapi.Snapshot{Sandboxes: []dashboardapi.Sandbox{{Name: "dev", State: dashboardapi.Running}}},
				ResourceLimits: dashboardapi.ResourceLimits{MaxVCPUs: 8},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/dashboard/actions":
			if err := json.NewDecoder(r.Body).Decode(&action); err != nil {
				t.Error(err)
			}
			if action.Secret != nil {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "reflected " + action.Secret.Value.Raw()})
				return
			}
			_ = json.NewEncoder(w).Encode(dashboardapi.ActionResult{RestartRequired: true})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/dashboard/packets/dev":
			if err := json.NewDecoder(r.Body).Decode(&capture); err != nil {
				t.Error(err)
			}
			_ = json.NewEncoder(w).Encode(packetcapture.Snapshot{Active: true, Next: 9})
		default:
			http.NotFound(w, r)
		}
	}))
	client, err := Dial(profile, testToken)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	host, err := client.DashboardSnapshot(t.Context())
	if err != nil || len(host.Snapshot.Sandboxes) != 1 || host.ResourceLimits.MaxVCPUs != 8 {
		t.Fatalf("DashboardSnapshot = %+v, %v", host, err)
	}
	request := dashboardapi.SandboxConfigRequest{Name: "dev", SSH: true}
	result, err := client.DashboardAction(t.Context(), dashboardapi.ActionRequest{Action: "configure-sandbox", SandboxConfig: &request})
	if err != nil || !result.RestartRequired || action.SandboxConfig == nil || !action.SandboxConfig.SSH {
		t.Fatalf("DashboardAction = %+v, %v request=%+v", result, err, action)
	}
	secretValue := secret.Value("do-not-reflect-this")
	_, err = client.DashboardAction(t.Context(), dashboardapi.ActionRequest{Action: "add-secret", Secret: &dashboardapi.SecretRequest{Sandbox: "dev", Name: "TOKEN", Value: secretValue}})
	if err == nil || strings.Contains(err.Error(), secretValue.Raw()) || !strings.Contains(err.Error(), "[redacted]") {
		t.Fatalf("write-only value leaked through manager error: %v", err)
	}

	packets, err := client.CapturePackets(t.Context(), "dev", packetcapture.Request{Start: true, After: 3})
	if err != nil || !packets.Active || packets.Next != 9 || !capture.Start || capture.After != 3 {
		t.Fatalf("CapturePackets = %+v, %v request=%+v", packets, err, capture)
	}
}
