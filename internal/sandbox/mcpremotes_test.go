package sandbox

import (
	"strings"
	"testing"
)

func TestParseMCPRemote(t *testing.T) {
	spec, err := parseMCPRemote("name=github,url=https://api.githubcopilot.com/mcp/,auth=bearer:GITHUB_TOKEN,allow=read*,deny=admin*,redact=GH_PAT")
	if err != nil {
		t.Fatal(err)
	}
	if spec.Name != "github" || spec.AuthKind != "bearer" || spec.AuthRef != "GITHUB_TOKEN" {
		t.Fatalf("spec = %+v", spec)
	}
	if len(spec.Allow) != 1 || len(spec.Deny) != 1 || len(spec.RedactNames) != 1 {
		t.Fatalf("lists = %+v", spec)
	}

	spec, err = parseMCPRemote("name=corp,url=http://127.0.0.1:8080/mcp,auth=header:X-Api-Key:CORP_KEY")
	if err != nil {
		t.Fatal(err)
	}
	if spec.AuthKind != "header" || spec.AuthHeader != "X-Api-Key" || spec.AuthRef != "CORP_KEY" {
		t.Fatalf("header spec = %+v", spec)
	}

	for _, tc := range []struct{ spec, want string }{
		{"url=https://x.example/mcp", "name"},
		{"name=fs,url=https://x.example/mcp", "reserved"},
		{"name=bad name,url=https://x.example/mcp", "must match"},
		{"name=a__b,url=https://x.example/mcp", "'__'"},
		{"name=x", "url="},
		{"name=x,url=http://1.2.3.4/mcp", "plain HTTP"},
		{"name=x,url=https://169.254.169.254/latest", "non-public"},
		{"name=x,url=https://u:p@x.example/mcp", "credentials in the URL"},
		{"name=x,url=https://x.example/mcp,auth=oauth:claude", "unknown kind"},
		{"name=x,url=https://x.example/mcp,auth=bearer:", "want bearer:<name>"},
		{"name=x,url=https://x.example/mcp,auth=header:Bad Header:REF", "invalid header name"},
		{"name=x,url=https://x.example/mcp,auth=header:OnlyName", "want header:"},
		{"name=x,url=https://x.example/mcp,verbose=true", "unknown field"},
		{"name=x,url=https://x.example/mcp,dangling", "k=v"},
	} {
		_, err := parseMCPRemote(tc.spec)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want substring %q", tc.spec, err, tc.want)
		}
	}
}
