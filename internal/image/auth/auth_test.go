package auth

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ejpir/gantry/internal/atomicfile"
)

// withHome points the resolver at a synthetic HOME.
func withHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	old := homeDir
	homeDir = func() (string, error) { return home, nil }
	t.Cleanup(func() { homeDir = old })
	return home
}

func TestResolutionOrder(t *testing.T) {
	home := withHome(t)
	t.Setenv("GANTRY_REGISTRY_AUTH", "")

	// docker config: auths base64 for ghcr.io
	dockerDir := filepath.Join(home, ".docker")
	_ = os.MkdirAll(dockerDir, 0o755)
	b64 := base64.StdEncoding.EncodeToString([]byte("dockeruser:dockerpass"))
	_ = os.WriteFile(filepath.Join(dockerDir, "config.json"),
		[]byte(fmt.Sprintf(`{"auths":{"ghcr.io":{"auth":%q}}}`, b64)), 0o600)

	// gantry credentials: quay.io
	gd := filepath.Join(home, ".gantry")
	_ = os.MkdirAll(gd, 0o700)
	q64 := base64.StdEncoding.EncodeToString([]byte("gantryuser:gantrypass"))
	_ = os.WriteFile(filepath.Join(gd, "credentials.json"),
		[]byte(fmt.Sprintf(`{"auths":{"quay.io":{"auth":%q}}}`, q64)), 0o600)

	r := Resolve()
	c := r.For("ghcr.io")
	if c == nil || c.Username != "dockeruser" || c.Secret.Raw() != "dockerpass" {
		t.Errorf("ghcr.io: %+v", c)
	}
	c = r.For("quay.io")
	if c == nil || c.Username != "gantryuser" || c.Secret.Raw() != "gantrypass" {
		t.Errorf("quay.io: %+v", c)
	}
	if c := r.For("unknown.example.com"); c != nil {
		t.Errorf("unknown registry should be anonymous, got %+v", c)
	}

	// env beats every file
	t.Setenv("GANTRY_REGISTRY_AUTH", "ghcr.io=envuser:envpass")
	r = Resolve()
	c = r.For("ghcr.io")
	if c == nil || c.Username != "envuser" || c.Source != "GANTRY_REGISTRY_AUTH" {
		t.Errorf("env precedence: %+v", c)
	}
}

func TestDockerIONormalization(t *testing.T) {
	home := withHome(t)
	dockerDir := filepath.Join(home, ".docker")
	_ = os.MkdirAll(dockerDir, 0o755)
	b64 := base64.StdEncoding.EncodeToString([]byte("hubuser:hubpass"))
	// docker writes the legacy index URL as the auths key
	_ = os.WriteFile(filepath.Join(dockerDir, "config.json"),
		[]byte(fmt.Sprintf(`{"auths":{"https://index.docker.io/v1/":{"auth":%q}}}`, b64)), 0o600)
	r := Resolve()
	for _, reg := range []string{"docker.io", "index.docker.io", "registry-1.docker.io"} {
		c := r.For(reg)
		if c == nil || c.Username != "hubuser" {
			t.Errorf("%s should resolve the hub credential: %+v", reg, c)
		}
	}
}

// helperFixture writes a docker-credential-<name> script on PATH.
func helperFixture(t *testing.T, name, script string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell helper fixture")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "docker-credential-"+name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestHelperProtocol(t *testing.T) {
	home := withHome(t)
	helperFixture(t, "test", `case "$1" in
get) cat > /dev/null; echo '{"ServerURL":"ghcr.io","Username":"helpuser","Secret":"helpsecret"}' ;;
store) exit 0 ;;
erase) exit 0 ;;
esac`)
	dockerDir := filepath.Join(home, ".docker")
	_ = os.MkdirAll(dockerDir, 0o755)
	_ = os.WriteFile(filepath.Join(dockerDir, "config.json"),
		[]byte(`{"credHelpers":{"ghcr.io":"test"}}`), 0o600)

	r := Resolve()
	c := r.For("ghcr.io")
	if c == nil || c.Username != "helpuser" || c.Secret.Raw() != "helpsecret" {
		t.Errorf("helper resolution: %+v", c)
	}
	if !strings.Contains(c.Source, "docker-credential-test") {
		t.Errorf("source = %q", c.Source)
	}
}

func TestHelperIdentityToken(t *testing.T) {
	home := withHome(t)
	helperFixture(t, "test", `case "$1" in
get) cat > /dev/null; echo '{"ServerURL":"x","Username":"<token>","Secret":"id-token-123"}' ;;
esac`)
	dockerDir := filepath.Join(home, ".docker")
	_ = os.MkdirAll(dockerDir, 0o755)
	_ = os.WriteFile(filepath.Join(dockerDir, "config.json"), []byte(`{"credsStore":"test"}`), 0o600)
	r := Resolve()
	c := r.For("anything.example.com")
	if c == nil || !c.IdentityToken || c.Secret.Raw() != "id-token-123" {
		t.Errorf("identity token: %+v", c)
	}
}

func TestHelperFailureDegradesToAnonymous(t *testing.T) {
	home := withHome(t)
	helperFixture(t, "broken", "exit 1")
	dockerDir := filepath.Join(home, ".docker")
	_ = os.MkdirAll(dockerDir, 0o755)
	_ = os.WriteFile(filepath.Join(dockerDir, "config.json"), []byte(`{"credsStore":"broken"}`), 0o600)
	r := Resolve()
	if c := r.For("ghcr.io"); c != nil {
		t.Errorf("failing helper must degrade to anonymous, got %+v", c)
	}
}

func TestSecretRedaction(t *testing.T) {
	s := Secret("hunter2")
	for _, got := range []string{
		fmt.Sprint(s), s.String(), fmt.Sprintf("%v", s), fmt.Sprintf("%#v", s),
		fmt.Sprintf("cred=%v", struct{ S Secret }{s}),
	} {
		if strings.Contains(got, "hunter2") {
			t.Errorf("secret leaked via formatting: %q", got)
		}
	}
	if s.Raw() != "hunter2" {
		t.Error("Raw() must expose the value")
	}
}

func TestStorePlaintextFallbackWarns(t *testing.T) {
	withHome(t)
	r := Resolve()
	warn, err := r.Store("ghcr.io", "u", Secret("p"))
	if err != nil {
		t.Fatal(err)
	}
	if warn == "" || !strings.Contains(warn, "base64") {
		t.Errorf("plaintext fallback must warn loudly, got %q", warn)
	}
	// and it round-trips
	c := Resolve().For("ghcr.io")
	if c == nil || c.Username != "u" || c.Secret.Raw() != "p" {
		t.Errorf("round-trip: %+v", c)
	}
	if err := Resolve().Erase("ghcr.io"); err != nil {
		t.Fatal(err)
	}
	if c := Resolve().For("ghcr.io"); c != nil {
		t.Error("erase left a credential")
	}
}

func TestStoreReloadsCredentialsUnderLock(t *testing.T) {
	withHome(t)
	first, second := Resolve(), Resolve()
	if _, err := first.Store("one.example", "one", Secret("first")); err != nil {
		t.Fatal(err)
	}
	if _, err := second.Store("two.example", "two", Secret("second")); err != nil {
		t.Fatal(err)
	}

	got := Resolve()
	for registry, username := range map[string]string{
		"one.example": "one",
		"two.example": "two",
	} {
		credential := got.For(registry)
		if credential == nil || credential.Username != username {
			t.Fatalf("%s credential = %+v, want user %q", registry, credential, username)
		}
	}

	// Erasing through a stale resolver must preserve the other process's
	// later addition rather than rewriting its old in-memory snapshot.
	if err := first.Erase("one.example"); err != nil {
		t.Fatal(err)
	}
	got = Resolve()
	if got.For("one.example") != nil {
		t.Fatal("erased credential remains")
	}
	if credential := got.For("two.example"); credential == nil || credential.Username != "two" {
		t.Fatalf("concurrent credential was lost: %+v", credential)
	}
}

func TestResolverRefreshesCacheAfterCommittedDurabilityError(t *testing.T) {
	withHome(t)
	r := Resolve()
	wantErr := errors.New("directory sync failed")
	r.writeFile = func(path string, data []byte, mode os.FileMode) error {
		if err := os.WriteFile(path, data, mode); err != nil {
			return err
		}
		return &atomicfile.CommitError{Err: wantErr}
	}

	warning, err := r.Store("registry.example", "user", Secret("secret"))
	if !atomicfile.Committed(err) || !errors.Is(err, wantErr) {
		t.Fatalf("Store error = %v, want committed durability error", err)
	}
	if warning == "" {
		t.Fatal("committed plaintext store lost its security warning")
	}
	if credential := r.For("registry.example"); credential == nil || credential.Username != "user" {
		t.Fatalf("resolver cache did not adopt committed credential: %+v", credential)
	}

	if err := r.Erase("registry.example"); !atomicfile.Committed(err) || !errors.Is(err, wantErr) {
		t.Fatalf("Erase error = %v, want committed durability error", err)
	}
	if credential := r.For("registry.example"); credential != nil {
		t.Fatalf("resolver cache retained committed erase: %+v", credential)
	}
}
