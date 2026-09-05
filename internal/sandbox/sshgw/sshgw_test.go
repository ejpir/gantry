package sshgw

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHostKeyPersistsAndIsPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ssh", "host_ed25519")
	first, err := EnsureHostKey(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := EnsureHostKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(first.PublicKey().Marshal()) != string(second.PublicKey().Marshal()) {
		t.Fatal("host key changed between loads")
	}
	assertPrivateHostKey(t, path)
}

func TestCorruptHostKeyFailsWithoutRekey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "host_ed25519")
	if err := os.WriteFile(path, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := EnsureHostKey(path)
	if err == nil || !strings.Contains(err.Error(), "delete it to regenerate") {
		t.Fatalf("EnsureHostKey error = %v", err)
	}
	data, readErr := os.ReadFile(path)
	if readErr != nil || string(data) != "not a key" {
		t.Fatalf("corrupt key was modified: data=%q err=%v", data, readErr)
	}
}

func TestGatewayUserMapsOnlyDefaultSentinel(t *testing.T) {
	for _, test := range []struct {
		requested string
		want      string
	}{
		{requested: "", want: "gantry"},
		{requested: DefaultUserSentinel, want: "gantry"},
		{requested: "root", want: "root"},
		{requested: "alice", want: "alice"},
	} {
		if got := gatewayUser(test.requested, "gantry"); got != test.want {
			t.Errorf("gatewayUser(%q) = %q, want %q", test.requested, got, test.want)
		}
	}
}

func TestEnvironmentAllowlist(t *testing.T) {
	for _, name := range []string{"TERM", "LANG", "LC_ALL", "COLORTERM", "TERM_PROGRAM"} {
		if !allowedEnv(name) {
			t.Errorf("%s should be allowed", name)
		}
	}
	for _, name := range []string{"PATH", "LD_PRELOAD", "GITHUB_TOKEN", "LC_", "TERM_PROGRAM_VERSION"} {
		if allowedEnv(name) {
			t.Errorf("%s should be refused", name)
		}
	}
}

func TestDirectTCPIPLoopbackPolicy(t *testing.T) {
	for _, target := range []struct {
		host string
		port uint32
	}{
		{"127.0.0.1", 1}, {"::1", 65535},
	} {
		if err := ValidateLoopbackTarget(target.host, target.port); err != nil {
			t.Errorf("target %s:%d: %v", target.host, target.port, err)
		}
	}
	for _, target := range []struct {
		host string
		port uint32
	}{
		{"localhost", 80}, {"8.8.8.8", 53}, {"127.0.0.2", 80}, {"::ffff:127.0.0.1", 80}, {"127.0.0.1", 0}, {"::1", 65536},
	} {
		if err := ValidateLoopbackTarget(target.host, target.port); err == nil || err.Error() != GenericChannelRefusal() {
			t.Errorf("target %s:%d accepted or leaked policy detail: %v", target.host, target.port, err)
		}
	}
}
