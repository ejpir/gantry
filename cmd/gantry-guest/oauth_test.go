package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/ejpir/gantry/internal/sandbox/credhelper/credproto"
)

func TestOAuthLoginUsesHostRegistration(t *testing.T) {
	for _, name := range []string{"claude", "codex", "github", "company-mcp"} {
		t.Run(name, func(t *testing.T) {
			var output bytes.Buffer
			calls := 0
			err := oauthLogin(context.Background(), name, func(req credproto.Request) (credproto.Response, error) {
				calls++
				if req.Provider != name || req.ClientID != "" || req.Verifier != "" || req.AuthorizeURL != "" {
					t.Fatal("guest tried to define the OAuth flow")
				}
				if calls == 1 {
					if req.Op != credproto.OpOAuthLogin {
						t.Fatal("not a name-only login")
					}
					return credproto.Response{State: "host-state", AuthorizeURL: "https://example.com/login", UserCode: "ABCD-EFGH"}, nil
				}
				if req.Op != credproto.OpOAuthStatus || req.State != "host-state" {
					t.Fatal("wrong status request")
				}
				return credproto.Response{OK: true, Message: "login complete"}, nil
			}, &output)
			if err != nil {
				t.Fatal(err)
			}
			for _, text := range []string{"https://example.com/login", "ABCD-EFGH", "login complete"} {
				if !strings.Contains(output.String(), text) {
					t.Errorf("missing browser instruction %s", text)
				}
			}
		})
	}
}

func TestOAuthLoginRefusesHostError(t *testing.T) {
	var output bytes.Buffer
	err := oauthLogin(context.Background(), "missing", func(credproto.Request) (credproto.Response, error) {
		return credproto.Response{Error: "unknown provider"}, nil
	}, &output)
	if err == nil || output.Len() != 0 {
		t.Fatal("host error did not fail closed")
	}
}
