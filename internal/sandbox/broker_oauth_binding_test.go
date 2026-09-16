package sandbox

import (
	"testing"

	"github.com/ejpir/gantry/internal/oauthprovider"
	"github.com/ejpir/gantry/internal/sandbox/credhelper"
	"github.com/ejpir/gantry/internal/sandbox/credhelper/credproto"
	"github.com/ejpir/gantry/internal/sandbox/oauthtokens"
	"github.com/ejpir/gantry/internal/secret"
)

func TestCustomCustodyCredentialBindingAndPrecedence(t *testing.T) {
	cm := genericCustody(t, oauthprovider.Spec{
		Provider: "github-work", AuthorizeURL: "https://github.com/login/oauth/authorize",
		TokenURL: "https://github.com/login/oauth/access_token", ClientID: "public-client",
		CredentialHosts: []string{"github.com"},
	})
	for _, set := range []oauthtokens.TokenSet{
		{Provider: "github", AccessToken: "default-access"},
		{Provider: "github-work", AccessToken: "work-access"},
	} {
		if err := cm.registry.Put(set); err != nil {
			t.Fatal(err)
		}
	}
	helper := credhelper.New(cm.br.resolveCredential, func(string) bool { return true }, nil)
	if got := helper.Decide(credproto.Request{Host: "github.com"}); got.Password != "work-access" {
		t.Fatal("configured binding did not precede built-in GitHub")
	}
	for _, host := range []string{"api.github.com", "github.com.evil.example", "other.example"} {
		if got := helper.Decide(credproto.Request{Host: host}); got.Password != "" {
			t.Fatal("access token escaped exact host binding")
		}
	}
	cm.br.secretStore = secret.NewStore(func(string) (string, bool) { return "explicit-access", true }, nil)
	cm.br.secretStore.Put("GIT_TOKEN", secret.Source{Kind: secret.SourceEnv, Ref: "GIT_TOKEN", Binding: "github.com"})
	if got := helper.Decide(credproto.Request{Host: "github.com"}); got.Password != "explicit-access" {
		t.Fatal("explicit secret lost precedence")
	}
	cm.br.secretStore.Remove("GIT_TOKEN")
	if err := cm.registry.Delete("github-work"); err != nil {
		t.Fatal(err)
	}
	if got := helper.Decide(credproto.Request{Host: "github.com"}); got.Password != "" {
		t.Fatal("revoked configured binding silently fell back to another account")
	}
}
