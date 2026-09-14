package mcpworker

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	workerapi "github.com/ejpir/gantry/internal/mcpworker"
	"github.com/ejpir/gantry/internal/workerproto"
)

func TestOrganizationBrokerGatesAuthorityAndRejectsForgedInput(t *testing.T) {
	checks := 0
	worker := &Worker{servers: map[string]Server{"remote": {
		Config:    workerapi.ServerConfig{Name: "remote", URL: "https://example.com/mcp", Credential: true},
		Authorize: func(_ context.Context, action, tool string) error { checks++; return fmt.Errorf("denied") },
		Credential: func() (workerapi.CredentialResponse, error) {
			t.Fatal("denied credential resolved")
			return workerapi.CredentialResponse{}, nil
		},
	}}, sessionCapabilities: map[string]struct{}{}}
	capability, err := worker.registerSessionCapability()
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(workerapi.CredentialRequest{Server: "remote", Session: capability})
	if _, err := worker.credential(workerproto.Request{Body: body}); err == nil {
		t.Fatal("credential released")
	}
	if err := worker.openWorkerStream(context.Background(), workerapi.OpenRequest{Kind: workerapi.StreamRemote, Server: "remote", Session: capability}, nil); err == nil {
		t.Fatal("remote dial was not gated")
	}
	if checks != 2 {
		t.Fatalf("authority checks=%d", checks)
	}
	valid := workerapi.AuthorizationRequest{Server: "remote", Session: capability, Action: "mcp.tools.call", Tool: "read_file"}
	body, _ = json.Marshal(valid)
	if _, err := worker.authorize(workerproto.Request{Body: body}); err == nil {
		t.Fatal("denied tool allowed")
	}
	for name, mutate := range map[string]func(*workerapi.AuthorizationRequest){
		"session": func(r *workerapi.AuthorizationRequest) { r.Session = "00000000000000000000000000000000" },
		"server":  func(r *workerapi.AuthorizationRequest) { r.Server = "other" },
		"action":  func(r *workerapi.AuthorizationRequest) { r.Action = "credential.use" },
	} {
		t.Run(name, func(t *testing.T) {
			request := valid
			mutate(&request)
			body, _ := json.Marshal(request)
			before := checks
			if _, err := worker.authorize(workerproto.Request{Body: body}); err == nil {
				t.Fatal("forged request accepted")
			}
			if checks != before {
				t.Fatal("forged request reached policy evaluator")
			}
		})
	}
	body = []byte(fmt.Sprintf(`{"server":"remote","session":%q,"action":"mcp.tools.call","tool":"read_file","profile":"admin"}`, capability))
	if _, err := worker.authorize(workerproto.Request{Body: body}); err == nil {
		t.Fatal("worker could supply a profile")
	}
}
