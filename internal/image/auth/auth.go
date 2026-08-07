// Package auth resolves registry credentials without ever implementing a
// keychain: GANTRY_REGISTRY_AUTH, gantry's own credentials.json, Docker's
// config (helpers and plaintext), Podman's auth files, then anonymous —
// first hit wins. Helpers speak the docker-credential-* protocol.
//
// The two load-bearing rules (docs/oci-images.md): credentials never
// reach the guest, and they never reach the sandbox daemon — pulls happen
// in the CLI process before the VM exists.
package auth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Secret is a credential whose value cannot leak into logs: String and
// GoString are redacted, and it never appears in a debug header dump.
type Secret string

func (s Secret) String() string   { return "<redacted>" }
func (s Secret) GoString() string { return "<redacted>" }

// Raw exposes the value for the single place that needs it (building an
// Authorization header). Everywhere else, keep it a Secret.
func (s Secret) Raw() string { return string(s) }

// Credential is one resolved registry login. IdentityToken means the
// secret is an identity/refresh token (helpers signal this with the
// username "<token>"), which changes the token-endpoint grant.
type Credential struct {
	Username      string
	Secret        Secret
	IdentityToken bool
	Source        string // where it came from ("env", "docker config credsStore(osxkeychain)", ...)
}

// dockerConfig mirrors the pieces of ~/.docker/config.json and the
// podman/skopeo auth files (same schema for auths).
type dockerConfig struct {
	Auths map[string]struct {
		Auth          string `json:"auth"`
		IdentityToken string `json:"identitytoken"`
	} `json:"auths"`
	CredsStore  string            `json:"credsStore"`
	CredHelpers map[string]string `json:"credHelpers"`
}

// Resolver finds credentials for registries. Construct with Resolve.
type Resolver struct {
	gantryCfg   *dockerConfig // ~/.gantry/credentials.json (also written by login)
	gantryPath  string
	dockerCfg   *dockerConfig
	podmanCfgs  []*dockerConfig
	envCreds    map[string]*Credential
	parseErrors []error // found-but-unparseable config files
}

var (
	homeDir     = os.UserHomeDir
	xdgRuntime  = func() string { return os.Getenv("XDG_RUNTIME_DIR") }
	lookupPath  = exec.LookPath
	runHelperFn = runHelper
)

// Resolve builds a Resolver from the environment and config files.
// Missing files are fine — each source is optional.
func Resolve() *Resolver {
	r := &Resolver{envCreds: map[string]*Credential{}}

	// 1. GANTRY_REGISTRY_AUTH: HOST=USER:SECRET, repeatable with ","
	//    (limitation: a secret containing a comma cannot be expressed
	//    here — use gantry image login or a docker config instead)
	if v := os.Getenv("GANTRY_REGISTRY_AUTH"); v != "" {
		for _, pair := range strings.Split(v, ",") {
			host, cred, ok := strings.Cut(pair, "=")
			if !ok {
				continue
			}
			user, secret, _ := strings.Cut(cred, ":")
			r.envCreds[normalize(host)] = &Credential{
				Username: user, Secret: Secret(secret), Source: "GANTRY_REGISTRY_AUTH",
			}
		}
	}

	home, _ := homeDir()
	r.gantryPath = filepath.Join(home, ".gantry", "credentials.json")
	load := func(path string) *dockerConfig {
		c, err := readConfig(path)
		if err != nil {
			r.parseErrors = append(r.parseErrors, err)
		}
		return c
	}
	r.gantryCfg = load(r.gantryPath)
	r.dockerCfg = load(filepath.Join(home, ".docker", "config.json"))
	if x := xdgRuntime(); x != "" {
		r.podmanCfgs = append(r.podmanCfgs, load(filepath.Join(x, "containers", "auth.json")))
	}
	r.podmanCfgs = append(r.podmanCfgs, load(filepath.Join(home, ".config", "containers", "auth.json")))
	return r
}

// ParseErrors reports credential files that were found but could not be
// parsed (they were skipped, so pulls degraded to anonymous).
func (r *Resolver) ParseErrors() []error { return r.parseErrors }

// readConfig returns (nil, nil) when the file is absent and (nil, err)
// when it exists but is unparseable — a JSON typo must not silently
// become a confusing anonymous 401; Resolver.ParseErrors surfaces it.
func readConfig(path string) (*dockerConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil
	}
	var c dockerConfig
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, nil
}

// normalize maps docker.io's many spellings to one lookup key.
func normalize(reg string) string {
	switch strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(reg, "https://"), "http://"), "/") {
	case "docker.io", "index.docker.io", "index.docker.io/v1", "registry-1.docker.io":
		return "docker.io"
	}
	return strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(reg, "https://"), "http://"), "/")
}

// For returns the credential for a registry, or nil for anonymous.
// Resolution order (first hit wins): env, gantry store, docker config,
// podman configs.
func (r *Resolver) For(registry string) *Credential {
	key := normalize(registry)
	if c, ok := r.envCreds[key]; ok {
		return c
	}
	if c := r.fromConfig(r.gantryCfg, key, "gantry credentials.json"); c != nil {
		return c
	}
	if c := r.fromConfig(r.dockerCfg, key, "docker config"); c != nil {
		return c
	}
	for i, pc := range r.podmanCfgs {
		if c := r.fromAuths(pc, key, fmt.Sprintf("podman auth.json #%d", i+1)); c != nil {
			return c
		}
	}
	return nil
}

// fromConfig tries credHelpers[host], then credsStore, then auths[host].
func (r *Resolver) fromConfig(cfg *dockerConfig, key, source string) *Credential {
	if cfg == nil {
		return nil
	}
	if helper, ok := cfg.CredHelpers[key]; ok {
		if c := r.fromHelper(helper, key); c != nil {
			c.Source = fmt.Sprintf("%s credHelpers[%s] (docker-credential-%s)", source, key, helper)
			return c
		}
	}
	if cfg.CredsStore != "" {
		if c := r.fromHelper(cfg.CredsStore, key); c != nil {
			c.Source = fmt.Sprintf("%s credsStore (docker-credential-%s)", source, cfg.CredsStore)
			return c
		}
	}
	return r.fromAuths(cfg, key, source)
}

// fromAuths decodes the base64 plaintext entry (what `docker login`
// writes when no helper is configured).
func (r *Resolver) fromAuths(cfg *dockerConfig, key, source string) *Credential {
	if cfg == nil {
		return nil
	}
	for k, entry := range cfg.Auths {
		if normalize(k) != key {
			continue
		}
		if entry.IdentityToken != "" {
			return &Credential{Secret: Secret(entry.IdentityToken), IdentityToken: true, Source: source + " auths (identity token)"}
		}
		if entry.Auth == "" {
			continue
		}
		dec, err := base64.StdEncoding.DecodeString(entry.Auth)
		if err != nil {
			continue
		}
		user, secret, _ := strings.Cut(string(dec), ":")
		return &Credential{Username: user, Secret: Secret(secret), Source: source + " auths (base64)"}
	}
	return nil
}

// fromHelper shells out to docker-credential-<name> get. A failing or
// missing helper degrades to nil (anonymous), never to a pull crash.
func (r *Resolver) fromHelper(helper, serverURL string) *Credential {
	out, err := runHelperFn(helper, "get", serverURL)
	if err != nil {
		return nil
	}
	var resp struct {
		ServerURL string `json:"ServerURL"`
		Username  string `json:"Username"`
		Secret    string `json:"Secret"`
	}
	if json.Unmarshal(out, &resp) != nil || resp.Secret == "" {
		return nil
	}
	c := &Credential{Username: resp.Username, Secret: Secret(resp.Secret)}
	if resp.Username == "<token>" {
		c.IdentityToken = true
	}
	return c
}

// Store saves a credential via the configured helper (preferred) or as
// base64 in gantry's own credentials.json (mode 0600). Returns a warning
// for the plaintext path — base64 is encoding, not encryption, and the
// user should hear it.
func (r *Resolver) Store(registry, username string, secret Secret) (warning string, err error) {
	key := normalize(registry)
	if helper := r.configuredHelper(key); helper != "" {
		err := storeViaHelper(helper, key, username, secret)
		return "", err
	}
	cfg := r.gantryCfg
	if cfg == nil {
		cfg = &dockerConfig{Auths: map[string]struct {
			Auth          string `json:"auth"`
			IdentityToken string `json:"identitytoken"`
		}{}}
	}
	if cfg.Auths == nil {
		cfg.Auths = map[string]struct {
			Auth          string `json:"auth"`
			IdentityToken string `json:"identitytoken"`
		}{}
	}
	entry := cfg.Auths[key]
	entry.Auth = base64.StdEncoding.EncodeToString([]byte(username + ":" + secret.Raw()))
	cfg.Auths[key] = entry
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(r.gantryPath), 0o700); err != nil {
		return "", err
	}
	if err := os.WriteFile(r.gantryPath, b, 0o600); err != nil {
		return "", err
	}
	r.gantryCfg = cfg
	return "no docker-credential-* helper configured: stored base64-encoded in ~/.gantry/credentials.json (0600) — base64 is encoding, not encryption", nil
}

// Erase removes a credential (helper erase, then our file).
func (r *Resolver) Erase(registry string) error {
	key := normalize(registry)
	if helper := r.configuredHelper(key); helper != "" {
		_ = eraseViaHelper(helper, key) // best-effort; the helper may not know it
	}
	if r.gantryCfg != nil {
		delete(r.gantryCfg.Auths, key)
		b, err := json.MarshalIndent(r.gantryCfg, "", "  ")
		if err == nil {
			_ = os.WriteFile(r.gantryPath, b, 0o600)
		}
	}
	return nil
}

func (r *Resolver) configuredHelper(key string) string {
	if r.gantryCfg != nil && r.gantryCfg.CredsStore != "" {
		return r.gantryCfg.CredsStore
	}
	if r.dockerCfg != nil {
		if h, ok := r.dockerCfg.CredHelpers[key]; ok {
			return h
		}
		if r.dockerCfg.CredsStore != "" {
			return r.dockerCfg.CredsStore
		}
	}
	return ""
}

// Row is one line of the credentials table.
type Row struct {
	Registry string
	Credential
}

// Table describes the resolution for inspection (`gantry image
// credentials`): what we'd use for each known registry, and why.
func (r *Resolver) Table(registries []string) []Row {
	out := []Row{}
	seen := map[string]bool{}
	for _, reg := range registries {
		key := normalize(reg)
		if seen[key] {
			continue
		}
		seen[key] = true
		row := Row{Registry: key, Credential: Credential{Username: "(anonymous)", Source: "-"}}
		if c := r.For(key); c != nil {
			row.Credential = *c
		}
		out = append(out, row)
	}
	return out
}

// ---------------- docker-credential-* protocol ----------------

// runHelper invokes docker-credential-<name> <verb> with input on stdin.
func runHelper(name, verb, input string) ([]byte, error) {
	bin, err := lookupPath("docker-credential-" + name)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(bin, verb)
	cmd.Stdin = strings.NewReader(input)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("docker-credential-%s %s: %w", name, verb, err)
	}
	return out, nil
}

func storeViaHelper(helper, serverURL, username string, secret Secret) error {
	payload, _ := json.Marshal(map[string]string{
		"ServerURL": serverURL, "Username": username, "Secret": secret.Raw(),
	})
	_, err := runHelperFn(helper, "store", string(payload))
	return err
}

func eraseViaHelper(helper, serverURL string) error {
	_, err := runHelperFn(helper, "erase", serverURL)
	return err
}
