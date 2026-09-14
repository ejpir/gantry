package mcpgw

import (
	"context"
	"fmt"
	"testing"

	"github.com/ejpir/gantry/internal/policy"
	"github.com/ejpir/gantry/internal/policy/policytest"
)

func TestOrganizationListAndCallAreIndependentGates(t *testing.T) {
	engine, err := policy.New(policytest.Signed(t, policy.Profile{Rules: []policy.Rule{
		{ID: "list", Effect: "allow", Action: policy.MCPList, Server: "fs", Tool: "echo"},
		{ID: "connect", Effect: "allow", Action: policy.MCPConnect, Server: "fs"},
	}}), nil)
	if err != nil {
		t.Fatal(err)
	}
	upstream := &fakeServer{respond: echoRespond}
	g, err := New(nil, fakeSpawn(t, upstream), []Server{{Name: "fs", Argv: []string{"fake"}, Tools: ToolPolicy{Allow: []string{"*"}},
		Authorize: func(ctx context.Context, session, action, tool string) error {
			if session == "" {
				return fmt.Errorf("missing session")
			}
			return engine.Authorize(ctx, action, policy.Resource{Server: "fs", Tool: tool})
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	results := decodeResults(t, runSession(t, g, []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"fs__echo","arguments":{"secret":"never-forward-this"}}}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"fs__hidden_admin"}}`,
	}))
	tools := results["1"]["result"].(map[string]any)["tools"].([]any)
	if len(tools) != 1 || tools[0].(map[string]any)["name"] != "fs__echo" {
		t.Fatalf("unexpected exposed tools: %+v", tools)
	}
	if results["2"]["error"] == nil || results["3"]["error"] == nil {
		t.Fatal("listing permission was reused for invocation")
	}
	if upstream.sawCall("echo") || upstream.sawCall("hidden_admin") {
		t.Fatal("denied invocation reached upstream")
	}
}
