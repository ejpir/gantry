package credhelper

import (
	"bufio"
	"encoding/json"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/ejpir/gantry/internal/sandbox/credhelper/credproto"
	"github.com/ejpir/gantry/internal/secret"
)

func TestHostMatches(t *testing.T) {
	for _, tc := range []struct {
		pattern, host string
		want          bool
	}{
		{"github.com", "github.com", true},
		{"github.com", "api.github.com", false},
		{"*.github.com", "api.github.com", true},
		{"*.github.com", "github.com", true}, // wildcard covers the bare suffix
		{"*.github.com", "evilsgithub.com", false},
		{"github.com.", "github.com", true}, // trailing-dot normalization
		{"GITHUB.COM", "github.com", true},  // case-insensitive
	} {
		if got := HostMatches(tc.pattern, tc.host); got != tc.want {
			t.Fatalf("HostMatches(%q, %q) = %v, want %v", tc.pattern, tc.host, got, tc.want)
		}
	}
}

func TestDecideGates(t *testing.T) {
	values := map[string]secret.Value{"GH": "tok-1", "GONE": ""}
	delete(values, "GONE") // bound but no value held
	bindings := map[string]string{"GH": "*.github.com", "GONE": "gitlab.com"}

	var logs []string
	var mu sync.Mutex
	logf := func(f string, a ...any) { mu.Lock(); logs = append(logs, f); mu.Unlock() }

	for _, tc := range []struct {
		name    string
		allowed func(string) bool
		host    string
		want    string // expected password; "" means withheld
		wantLog string
	}{
		{"delivers bound credential", func(string) bool { return true }, "api.github.com", "tok-1", "delivered"},
		{"withholds without binding", func(string) bool { return true }, "gitlab.example.com", "", "no authorizing binding"},
		{"withholds when value is gone", func(string) bool { return true }, "gitlab.com", "", "no value held"},
		{"denies when egress blocks", func(string) bool { return false }, "api.github.com", "", "egress policy"},
		{"rejects malformed host", func(string) bool { return true }, "bad_host!", "", "malformed host"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs = nil
			b := New(NewResolver(values, bindings), tc.allowed, logf)
			resp := b.Decide(Request{Host: tc.host, Path: "org/repo"})
			if resp.Password != tc.want {
				t.Fatalf("password = %q, want %q", resp.Password, tc.want)
			}
			if tc.want != "" && resp.Username != Username {
				t.Fatalf("username = %q, want %q", resp.Username, Username)
			}
			if len(logs) != 1 || !strings.Contains(logs[0], tc.wantLog) {
				t.Fatalf("logs = %v, want one entry containing %q", logs, tc.wantLog)
			}
		})
	}
}

func TestResolverDeterministicPrecedence(t *testing.T) {
	// Two bindings cover the same host: the lexically first secret name wins,
	// on every call.
	values := map[string]secret.Value{"B": "tok-b", "A": "tok-a"}
	bindings := map[string]string{"B": "github.com", "A": "*.github.com"}
	resolve := NewResolver(values, bindings)
	for range 10 {
		name, v, res := resolve("github.com")
		if res != OK || name != "A" || v.Raw() != "tok-a" {
			t.Fatalf("resolve = %q/%v, want A/tok-a", name, res)
		}
	}
}

// TestServeRoundTrip drives the wire protocol end to end over a real
// listener, including the empty-object "no credential" answer.
func TestServeRoundTrip(t *testing.T) {
	ln, err := net.Listen("unix", t.TempDir()+"/1027.sock")
	if err != nil {
		t.Fatal(err)
	}
	b := New(NewResolver(map[string]secret.Value{"GH": "wire-tok"}, map[string]string{"GH": "github.com"}), nil, nil)
	done := make(chan error, 1)
	go func() { done <- b.Serve(ln) }()
	defer func() { _ = ln.Close() }()

	ask := func(host string) Response {
		t.Helper()
		c, err := net.Dial("unix", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = c.Close() }()
		if _, err := c.Write([]byte(`{"host":"` + host + `"}` + "\n")); err != nil {
			t.Fatal(err)
		}
		line, err := bufio.NewReader(c).ReadBytes('\n')
		if err != nil {
			t.Fatal(err)
		}
		var resp Response
		if err := json.Unmarshal(line, &resp); err != nil {
			t.Fatal(err)
		}
		return resp
	}

	if resp := ask("github.com"); resp.Password != "wire-tok" || resp.Username != Username {
		t.Fatalf("bound response = %+v", resp)
	}
	if resp := ask("example.com"); resp != (Response{}) {
		t.Fatalf("unbound response = %+v, want empty", resp)
	}
}

// With custody off, oauth.* ops get a clear error, never a hang; with a
// handler installed they route to it.
func TestOAuthOpRouting(t *testing.T) {
	b := New(func(string) (string, secret.Value, Resolution) { return "", "", NoBinding }, nil, func(string, ...any) {})
	resp := b.Decide(Request{Op: credproto.OpOAuthBegin, Provider: "claude"})
	if resp.Error == "" {
		t.Fatal("oauth op without a handler: want a custody-disabled error")
	}
	b.SetOAuthHandler(func(req Request) Response {
		return Response{Message: "routed:" + req.Provider}
	})
	resp = b.Decide(Request{Op: credproto.OpOAuthBegin, Provider: "claude"})
	if resp.Message != "routed:claude" {
		t.Fatalf("oauth op not routed: %+v", resp)
	}
	// Credential gets are unaffected by the handler.
	if resp := b.Decide(Request{Host: "git.test"}); resp != (Response{}) {
		t.Fatalf("credential get with handler installed = %+v, want empty", resp)
	}
}
