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
	canonical, err := Encode(remote)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip, err := Parse(canonical)
	if err != nil {
		t.Fatal(err)
	}
	roundTripCanonical, err := Encode(roundTrip)
	if err != nil {
		t.Fatal(err)
	}
	if roundTripCanonical != canonical || len(roundTrip.Allow) != 2 || len(roundTrip.Deny) != 1 || len(roundTrip.RedactNames) != 1 {
		t.Fatalf("round trip = %+v", roundTrip)
	}
}

func TestEncodeRemoteRejectsGrammarDelimiterInjection(t *testing.T) {
	for _, test := range []struct {
		name   string
		remote Remote
		want   string
	}{
		{
			name:   "URL injects auth",
			remote: Remote{Name: "leak", URL: "https://evil.example/mcp,auth=bearer:GITHUB_TOKEN"},
			want:   "url: comma is not allowed",
		},
		{
			name: "allow injects redaction",
			remote: Remote{
				Name: "leak", URL: "https://evil.example/mcp", Allow: []string{"read_*,redact=GITHUB_TOKEN"},
			},
			want: "allow: comma is not allowed",
		},
		{
			name: "deny injects auth",
			remote: Remote{
				Name: "leak", URL: "https://evil.example/mcp", Deny: []string{"admin_*,auth=bearer:GITHUB_TOKEN"},
			},
			want: "deny: comma is not allowed",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Encode(test.remote); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Encode() error = %v, want %q", err, test.want)
			}
		})
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
		{"name=first,name=second,url=https://example.com/mcp", "duplicate field"},
		{"name=bad,url=https://example.com/one,url=https://example.com/two", "duplicate field"},
		{"name=bad,url=https://example.com/mcp,auth=bearer:TOKEN,auth=bearer:OTHER", "duplicate field"},
	} {
		if _, err := Parse(test.raw); err == nil || !strings.Contains(err.Error(), test.want) {
			t.Errorf("Parse(%q) = %v, want %q", test.raw, err, test.want)
		}
	}
}
