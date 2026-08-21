package main

import (
	"strings"
	"testing"
)

func TestCodexCustodyUsesCLIRegisteredRedirectAndScopes(t *testing.T) {
	provider := guestOAuthProviders["codex"]
	if provider.callbackHost != "localhost" || provider.callbackPort != 1455 || provider.callbackPath != "/auth/callback" {
		t.Fatalf("codex callback = http://%s:%d%s", provider.callbackHost, provider.callbackPort, provider.callbackPath)
	}
	for _, scope := range []string{"openid", "offline_access", "api.connectors.read", "api.connectors.invoke"} {
		if !strings.Contains(provider.scope, scope) {
			t.Fatalf("codex scope %q is missing %q", provider.scope, scope)
		}
	}
	for _, key := range []string{"id_token_add_organizations", "codex_cli_simplified_flow"} {
		if provider.extraParams[key] != "true" {
			t.Fatalf("codex authorize parameter %s = %q", key, provider.extraParams[key])
		}
	}
	if provider.extraParams["originator"] != "codex_cli_rs" {
		t.Fatalf("codex originator = %q", provider.extraParams["originator"])
	}
}
