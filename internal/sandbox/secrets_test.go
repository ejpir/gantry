package sandbox

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"gantry/internal/secret"
)

// docs/secrets.md rule 1: the value never lands on host disk. The only
// persisted artifact is sandbox.json — assert a canary value appears
// nowhere in it while the NAME does.
func TestSandboxJSONNamesOnly(t *testing.T) {
	canary := "sk-canary-sandboxjson"
	os.Setenv("GANTRY_TEST_CANARY", canary)
	defer os.Unsetenv("GANTRY_TEST_CANARY")

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
	w.WriteString(secretsHandshakeJSON(map[string]secret.Value{
		"GITHUB_TOKEN": "ghp_canary",
		"NPM":          "npm_canary",
	}))
	w.Close()
	got := readSecretsHandshake(r)
	if len(got) != 2 || got["GITHUB_TOKEN"].Raw() != "ghp_canary" || got["NPM"].Raw() != "npm_canary" {
		t.Errorf("round-trip = %v", got)
	}

	r2, w2, _ := os.Pipe()
	w2.Close() // EOF, no handshake
	if got := readSecretsHandshake(r2); len(got) != 0 {
		t.Errorf("EOF handshake = %v, want empty", got)
	}
}
