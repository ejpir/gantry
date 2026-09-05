package sandbox

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ejpir/gantry/internal/sandbox/controlproto"
	"github.com/ejpir/gantry/internal/secret"
)

// docs/secrets.md rule 1: the value never lands on host disk. The only
// persisted artifact is sandbox.json — assert a canary value appears
// nowhere in it while the NAME does.
func TestSandboxJSONNamesOnly(t *testing.T) {
	canary := "sk-canary-sandboxjson"
	_ = os.Setenv("GANTRY_TEST_CANARY", canary)
	defer func() { _ = os.Unsetenv("GANTRY_TEST_CANARY") }()

	cfg, _, _ := resolveSandbox(t, "-secret", "GANTRY_TEST_CANARY")
	if len(cfg.SecretNames) != 1 || cfg.SecretNames[0] != "GANTRY_TEST_CANARY" {
		t.Fatalf("SecretNames = %v", cfg.SecretNames)
	}
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), canary) {
		t.Fatalf("sandbox.json contains the secret VALUE: %s", b)
	}
	if !strings.Contains(string(b), "GANTRY_TEST_CANARY") {
		t.Errorf("sandbox.json lost the secret NAME: %s", b)
	}
}

// NAME=literal is refused at resolution (argv is world-readable).
func TestSecretLiteralRefused(t *testing.T) {
	if _, _, err := resolveSandbox(t, "-secret", "TOKEN=sk-literal"); err == nil ||
		!strings.Contains(err.Error(), "refusing") {
		t.Errorf("err = %v, want the literal refusal", err)
	}
}

// The CLI→daemon handshake round-trips values over stdin, and a terminal
// or empty stdin degrades to no secrets (manual `gantry daemon`).
func TestSecretsHandshake(t *testing.T) {
	r, w, _ := os.Pipe()
	handshake, err := secretsHandshakeJSON(map[string]secret.Value{
		"GITHUB_TOKEN": "ghp_canary",
		"NPM":          "npm_canary",
	}, []secret.NamedSource{
		{Name: "FILE_TOK", Source: secret.Source{Kind: secret.SourceFile, Ref: "/run/secrets/tok", Binding: "git.test", Refresh: 2 * time.Second}},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.WriteString(handshake)
	_ = w.Close()
	got, gotSources, err := readSecretsHandshake(r)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got["GITHUB_TOKEN"].Raw() != "ghp_canary" || got["NPM"].Raw() != "npm_canary" {
		t.Errorf("round-trip = %v", got)
	}
	if len(gotSources) != 1 || gotSources[0].Name != "FILE_TOK" ||
		gotSources[0].Source.Kind != secret.SourceFile || gotSources[0].Source.Ref != "/run/secrets/tok" ||
		gotSources[0].Source.Binding != "git.test" || gotSources[0].Source.Refresh != 2*time.Second {
		t.Errorf("source round-trip = %+v", gotSources)
	}

	r2, w2, _ := os.Pipe()
	_ = w2.Close() // EOF, no handshake
	got, _, err = readSecretsHandshake(r2)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("EOF handshake = %v, want empty", got)
	}
}

func TestSameSecretSourcesIsSemantic(t *testing.T) {
	left := []secret.NamedSource{{
		Name: "TOKEN", Source: secret.Source{
			Kind: secret.SourceExec, Argv: []string{"helper", "token"}, Binding: "api.example", Refresh: time.Second,
		},
	}}
	right := []secret.NamedSource{{
		Name: "TOKEN", Source: secret.Source{
			Kind: secret.SourceExec, Argv: []string{"helper", "token"}, Binding: "api.example", Refresh: time.Second,
		},
	}}
	if !sameSecretSources(left, right) {
		t.Fatal("equivalent source lists did not match")
	}
	right[0].Source.Argv[1] = "other"
	if sameSecretSources(left, right) {
		t.Fatal("different source argv unexpectedly matched")
	}
	if sameSecretSources(nil, right) {
		t.Fatal("different source list lengths unexpectedly matched")
	}
	if !sameSecretSources(nil, []secret.NamedSource{}) {
		t.Fatal("nil and empty source lists should be equivalent")
	}
}

func TestSecretsHandshakeBounds(t *testing.T) {
	many := make(map[string]secret.Value, controlproto.SecretsHandshakeMaxEntries+1)
	for i := range controlproto.SecretsHandshakeMaxEntries + 1 {
		many[fmt.Sprintf("SECRET_%d", i)] = "x"
	}
	if _, err := secretsHandshakeJSON(many, nil); err == nil || !strings.Contains(err.Error(), "too many secrets") {
		t.Fatalf("entry-limit error = %v, want count rejection", err)
	}

	oversized := map[string]secret.Value{
		"TOKEN": secret.Value(strings.Repeat("x", controlproto.SecretsHandshakeMaxBytes)),
	}
	if _, err := secretsHandshakeJSON(oversized, nil); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized encode error = %v, want size rejection", err)
	}

	f, err := os.CreateTemp(t.TempDir(), "oversized-handshake")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteString(strings.Repeat("x", controlproto.SecretsHandshakeMaxBytes+1)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readSecretsHandshake(f); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("oversized read error = %v, want size rejection", err)
	}
}

// The daemon spawn scrubs exactly the injected secret keys from the
// environment it inherits: /proc/<pid>/environ is host state readable
// by the same uid, and the handshake already delivered the values.
// Everything else (HOME, proxy vars, GANTRY_* knobs) passes through.
func TestScrubbedEnv(t *testing.T) {
	environ := []string{
		"HOME=/home/u",
		"HTTPS_PROXY=http://proxy:3128",
		"GITHUB_TOKEN=ghp_canary",
		"NPM=npm_canary",
		"GANTRY_BOOT_TIMING=1",
		"EMPTYSECRET=",
	}
	got := scrubbedEnv(environ, map[string]secret.Value{
		"GITHUB_TOKEN": "ghp_canary",
		"NPM":          "npm_canary",
		"EMPTYSECRET":  "",
	})
	joined := strings.Join(got, "\n")
	for _, leaked := range []string{"GITHUB_TOKEN", "NPM=", "EMPTYSECRET"} {
		if strings.Contains(joined, leaked) {
			t.Errorf("scrubbed env still carries %q: %v", leaked, got)
		}
	}
	for _, kept := range []string{"HOME=/home/u", "HTTPS_PROXY=http://proxy:3128", "GANTRY_BOOT_TIMING=1"} {
		if !strings.Contains(joined, kept) {
			t.Errorf("scrubbed env lost %q: %v", kept, got)
		}
	}
	// No secrets: the block passes through untouched.
	if got := scrubbedEnv(environ, nil); len(got) != len(environ) {
		t.Errorf("no-secret scrub changed the block: %v", got)
	}
}
