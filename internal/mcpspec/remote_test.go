package mcpspec

import (
	"strings"
	"testing"
)

func TestRemoteRoundTrip(t *testing.T) {
	raw := "name=github,url=https://api.githubcopilot.com/mcp/,auth=header:X-Api-Key:GITHUB_TOKEN,allow=read_*,allow=list_*,deny=admin_*,redact=OTHER_TOKEN"
	remote, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if remote.Name != "github" || remote.AuthKind != "header" || remote.AuthHeader != "X-Api-Key" || remote.AuthRef != "GITHUB_TOKEN" {
		t.Fatalf("remote = %+v", remote)
	}
	roundTrip, err := Parse(remote.String())
	if err != nil {
		t.Fatal(err)
	}
	if roundTrip.String() != remote.String() || len(roundTrip.Allow) != 2 || len(roundTrip.Deny) != 1 || len(roundTrip.RedactNames) != 1 {
		t.Fatalf("round trip = %+v", roundTrip)
	}
}

func TestRemoteRejectsUnsafeOrUnstartableConfiguration(t *testing.T) {
	for _, test := range []struct {
		raw  string
		want string
	}{
		{"name=fs,url=https://example.com/mcp", "reserved"},
		{"name=metadata,url=https://169.254.169.254/latest", "non-public"},
		{"name=bad,url=https://example.com/mcp,auth=bearer:bad-name", "secret reference"},
		{"name=bad,url=https://example.com/mcp,allow=[", "bad tool pattern"},
		{"name=bad,url=https://example.com/mcp,redact=bad-name", "secret reference"},
	} {
		if _, err := Parse(test.raw); err == nil || !strings.Contains(err.Error(), test.want) {
			t.Errorf("Parse(%q) = %v, want %q", test.raw, err, test.want)
		}
	}
}
