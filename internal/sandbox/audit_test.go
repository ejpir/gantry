package sandbox

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/credhelper"
	"github.com/ejpir/gantry/internal/sandbox/credhelper/credproto"
	"github.com/ejpir/gantry/internal/secret"
)

func TestAuditRingBoundedAndOrdered(t *testing.T) {
	r := &auditRing{}
	for i := 0; i < auditRingCapacity+50; i++ {
		r.append(fmt.Sprintf("event-%d", i))
	}
	lines := r.tail()
	if len(lines) != auditRingCapacity {
		t.Fatalf("len = %d, want capacity %d", len(lines), auditRingCapacity)
	}
	if lines[0] != "event-50" || lines[len(lines)-1] != fmt.Sprintf("event-%d", auditRingCapacity+49) {
		t.Fatalf("tail window wrong: first %q last %q", lines[0], lines[len(lines)-1])
	}
}

// TestWarnBoundSecretsVsPolicy covers the start-time misconfiguration
// surface: a bound secret whose domain the egress allowlist does not
// cover must produce a warning at resolve time (the credhelper would
// refuse every guest request for it at runtime).
func TestAuditRingBoundsBytesAndEscapesControlCharacters(t *testing.T) {
	r := &auditRing{}
	line := "guest\nforged\r" + strings.Repeat("x", auditLineMaxBytes*2)
	for i := 0; i < auditRingCapacity; i++ {
		r.append(line)
	}
	lines := r.tail()
	if len(lines) == 0 || r.bytes > auditRingMaxBytes {
		t.Fatalf("ring lines=%d bytes=%d", len(lines), r.bytes)
	}
	for _, got := range lines {
		if strings.ContainsAny(got, "\r\n") {
			t.Fatalf("audit control character was not escaped: %q", got)
		}
		if len(got) > auditLineMaxBytes {
			t.Fatalf("audit line retained %d bytes", len(got))
		}
	}
}

func TestWarnBoundSecretsVsPolicy(t *testing.T) {
	dir := t.TempDir()
	pol := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(pol, []byte(`{"default":"deny","allowDomains":["github.com"],"rules":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var got []string
	r := &runResolver{
		flags:    &config.RunFlags{NetPol: &pol},
		progress: func(f string, a ...any) { got = append(got, fmt.Sprintf(f, a...)) },
	}
	src, err := secret.ParseNamedSource("AWS_CREDS@sts.amazonaws.com=@/secure/aws")
	if err != nil {
		t.Fatal(err)
	}
	r.warnBoundSecretsVsPolicy(
		[]string{"GH@github.com", "GL@gitlab.com", "AMBIENT"},
		[]secret.NamedSource{src},
	)
	if len(got) != 2 {
		t.Fatalf("warnings = %v, want exactly 2 (gitlab.com, sts.amazonaws.com)", got)
	}
	for _, want := range []string{"GL@gitlab.com", "AWS_CREDS"} {
		found := false
		for _, line := range got {
			if strings.Contains(line, want) && strings.Contains(line, "egress policy") == false && strings.Contains(line, "refuse") {
				found = true
			}
		}
		if !found {
			t.Fatalf("no warning naming %s in %v", want, got)
		}
	}

	// No allowlist configured: the policy does not filter by name, so no
	// warnings.
	pol2 := filepath.Join(dir, "policy2.json")
	if err := os.WriteFile(pol2, []byte(`{"default":"allow","rules":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	got = nil
	r.flags.NetPol = &pol2
	r.warnBoundSecretsVsPolicy([]string{"GL@gitlab.com"}, nil)
	if len(got) != 0 {
		t.Fatalf("warnings with name-blind policy = %v, want none", got)
	}

	// No -net-policy at all: nothing to check.
	got = nil
	empty := ""
	r.flags.NetPol = &empty
	r.warnBoundSecretsVsPolicy([]string{"GL@gitlab.com"}, nil)
	if len(got) != 0 {
		t.Fatalf("warnings without policy = %v, want none", got)
	}
}

// TestAuditTrailNeverLeaksSecretMaterial feeds adversarial secret values
// (newlines, format verbs, CRLF, JSON breakers, huge strings) through every
// audit-emitting path — credhelper decisions, secret-source failures,
// OAuth custody events — and asserts no trail line contains any value
// substring. The trail names secrets; it never quotes them.
func TestAuditTrailNeverLeaksSecretMaterial(t *testing.T) {
	markers := []string{
		"SEKRET-1-line1\nline2",
		"SEKRET-2-%s%v%n%x",
		"SEKRET-3-\r\nCRLF",
		`SEKRET-4-{"json":"break"}`,
		"SEKRET-5-" + strings.Repeat("A", 4096),
		"SEKRET-6-snowman-☃",
	}
	br := &broker{audit: &auditRing{}}
	logf := br.auditf // credhelper decision lines self-prefix "credhelper: "

	// Credhelper decisions across every gate, each with a nasty value
	// held for the bound name.
	for i, marker := range markers {
		name := fmt.Sprintf("TOK%d", i)
		values := map[string]secret.Value{name: secret.Value(marker)}
		bindings := map[string]string{name: "api.github.com"}
		b := credhelper.New(credhelper.NewResolver(values, bindings), func(string) bool { return true }, logf)
		if resp := b.Decide(credproto.Request{Host: "api.github.com"}); resp.Password != marker {
			t.Fatalf("delivery for %s did not round-trip", name)
		}
		bDeny := credhelper.New(credhelper.NewResolver(values, bindings), func(string) bool { return false }, logf)
		bDeny.Decide(credproto.Request{Host: "api.github.com"})
		bUnbound := credhelper.New(credhelper.NewResolver(values, nil), func(string) bool { return true }, logf)
		bUnbound.Decide(credproto.Request{Host: "gitlab.example.com"})
	}

	// Secret-source failures: the error path must name the secret, not
	// quote any value the source emitted before failing.
	storeLogf := func(f string, a ...any) {
		line := fmt.Sprintf(f, a...)
		br.audit.append(line)
	}
	st := secret.NewStore(os.LookupEnv, storeLogf)
	execSrc, err := secret.ParseNamedSource("BROKEN=!false")
	if err != nil {
		t.Fatal(err)
	}
	st.Put(execSrc.Name, execSrc.Source)
	if _, err := st.Resolve("BROKEN"); err == nil {
		t.Fatal("failing exec source must fail closed")
	}

	// Custody: a full login + refresh with a nasty access token; the
	// trail records lifecycle events, never token bytes.
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var grant map[string]string
		_ = json.NewDecoder(r.Body).Decode(&grant)
		w.Header().Set("Content-Type", "application/json")
		if grant["grant_type"] == "refresh_token" {
			_, _ = fmt.Fprintf(w, `{"access_token":%q,"refresh_token":"rt-nasty","expires_in":3600}`, markers[1])
			return
		}
		// 1s lifetime with the 5-minute refresh leeway: the set is due the
		// moment it lands (a zero expiry means "never schedule", not now).
		_, _ = fmt.Fprintf(w, `{"access_token":%q,"refresh_token":"rt-nasty","expires_in":1}`, markers[0])
	}))
	defer tokenSrv.Close()
	cm, _ := newTestCustody(t, tokenSrv)
	cm.br = br // share the audited broker
	req := beginReq("nasty-state-1")
	if resp := cm.handleOAuthOp(req); resp.Error != "" {
		t.Fatalf("begin: %s", resp.Error)
	}
	port := 8485
	if !cm.consumeCallback(port, mustParseURL(t, "http://127.0.0.1:8485/callback?code=c&state=nasty-state-1")) {
		t.Fatal("callback not consumed")
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		resp := cm.status(credproto.Request{Op: credproto.OpOAuthStatus, Provider: "claude", State: "nasty-state-1"})
		if resp.OK {
			break
		}
		if resp.Error != "" {
			t.Fatalf("status: %s", resp.Error)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, held := cm.registry.Get("claude"); !held {
		t.Fatal("no custody set held after login")
	}
	refreshed := false
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		for _, line := range br.audit.tail() {
			if strings.Contains(line, "access token refreshed and pushed") {
				refreshed = true
			}
		}
		if refreshed {
			break
		}
	}
	if !refreshed {
		t.Fatal("refresh loop did not emit the refreshed-and-pushed event")
	}

	for _, line := range br.audit.tail() {
		for _, marker := range markers {
			if strings.Contains(line, marker) {
				t.Fatalf("audit line leaks secret material %q: %q", marker, line)
			}
		}
	}
	if len(br.audit.tail()) == 0 {
		t.Fatal("audit trail empty — the paths above must have emitted events")
	}
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}
