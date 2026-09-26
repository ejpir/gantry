package controlcmd

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ejpir/gantry/internal/policy"
)

func readAuthoredPolicy(t *testing.T, dir, profile string) (*policy.Config, *policy.Engine) {
	t.Helper()
	c, err := policy.ReadConfig(filepath.Join(dir, "bundle.tar.gz"), filepath.Join(dir, "public.pem"), profile)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := policy.New(c, nil)
	if err != nil {
		t.Fatal(err)
	}
	return c, engine
}

func TestPolicyGenerateRestrictiveDefaultsAndReadOnlyMounts(t *testing.T) {
	base := t.TempDir()
	out := filepath.Join(base, "policy")
	mount := t.TempDir()
	canonical, err := canonicalPolicyMount(mount)
	if err != nil {
		t.Fatal(err)
	}
	before := time.Now()
	if code := CmdPolicy([]string{"generate", "-out", out, "-mount", mount, "-mount", mount, "-organization", "demo-org", "-revision", "demo-1", "-profile", "dev"}); code != 0 {
		t.Fatalf("generate exit = %d", code)
	}
	_, engine := readAuthoredPolicy(t, out, "dev")
	doc, err := policy.ReadDocument(filepath.Join(out, "source", "data.json"))
	if err != nil {
		t.Fatal(err)
	}
	p := doc.Profiles["dev"]
	if len(p.Rules) != 1 || p.Rules[0].Path != canonical || p.Rules[0].Action != policy.MountRead || len(p.Network.Rules) != 0 || len(p.Network.DNS) != 0 {
		t.Fatalf("unexpected generated permissions: %+v", p)
	}
	info := engine.Info()
	if info.Organization != "demo-org" || info.Revision != "demo-1" || info.Profile != "dev" || info.ExpiresAt.Before(before.Add(30*24*time.Hour)) || info.ExpiresAt.After(time.Now().Add(30*24*time.Hour)) {
		t.Fatalf("generated provenance/TTL = %+v", info)
	}
	for _, tc := range []struct {
		action   string
		resource policy.Resource
		allow    bool
	}{
		{policy.MountRead, policy.Resource{Path: canonical}, true},
		{policy.MountRead, policy.Resource{Path: filepath.Join(canonical, "child")}, true},
		{policy.MountRead, policy.Resource{Path: canonical + "-sibling"}, false},
		{policy.MountWrite, policy.Resource{Path: canonical}, false},
		{policy.MCPConnect, policy.Resource{Server: "fs"}, false},
		{policy.MCPList, policy.Resource{Server: "fs", Tool: "read_file"}, false},
		{policy.MCPCall, policy.Resource{Server: "fs", Tool: "read_file"}, false},
		{policy.CredentialUse, policy.Resource{Host: "github.com"}, false},
		{policy.NetworkConnect, policy.Resource{IP: "1.1.1.1", Protocol: "tcp", Port: 443}, false},
		{policy.NetworkResolve, policy.Resource{Host: "github.com"}, false},
	} {
		d := engine.Evaluate(context.Background(), tc.action, tc.resource)
		if (d.Effect == "allow") != tc.allow {
			t.Fatalf("generated permission %s %+v: %+v", tc.action, tc.resource, d)
		}
	}
	var files []string
	if err := filepath.WalkDir(out, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if runtime.GOOS != "windows" {
			info, err := entry.Info()
			if err != nil {
				return err
			}
			want := os.FileMode(0o600)
			if entry.IsDir() {
				want = 0o700
			}
			if info.Mode().Perm() != want {
				t.Errorf("%s permissions = %o, want %o", path, info.Mode().Perm(), want)
			}
		}
		if !entry.IsDir() {
			rel, err := filepath.Rel(out, path)
			if err != nil {
				return err
			}
			files = append(files, filepath.ToSlash(rel))
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if bytes.Contains(raw, []byte("PRIVATE KEY")) {
				t.Errorf("private key saved to %s", path)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(files, []string{"bundle.tar.gz", "public.pem", "source/data.json"}) {
		t.Fatalf("unexpected generated files: %v", files)
	}
	// Exclusive creation must not modify even one member of an existing set.
	original, err := os.ReadFile(filepath.Join(out, "bundle.tar.gz"))
	if err != nil {
		t.Fatal(err)
	}
	if code := CmdPolicy([]string{"generate", "-out", out}); code == 0 {
		t.Fatal("existing output overwritten")
	}
	after, err := os.ReadFile(filepath.Join(out, "bundle.tar.gz"))
	if err != nil || !bytes.Equal(after, original) {
		t.Fatal("overwrite refusal changed existing bundle")
	}
}

func TestPolicyGenerateNoImplicitMountOrReusableKey(t *testing.T) {
	var keys [][]byte
	for range 2 {
		out := filepath.Join(t.TempDir(), "generated")
		if code := CmdPolicy([]string{"generate", "-out", out, "-ttl", "12h"}); code != 0 {
			t.Fatalf("generate exit = %d", code)
		}
		c, _ := readAuthoredPolicy(t, out, "developer")
		keys = append(keys, []byte(c.PublicKey))
		doc, err := policy.ReadDocument(filepath.Join(out, "source", "data.json"))
		if err != nil || len(doc.Profiles["developer"].Rules) != 0 || doc.Organization != "local-test" || !strings.HasPrefix(doc.Revision, "generated-") {
			t.Fatalf("defaults = %+v, error %v", doc, err)
		}
	}
	if bytes.Equal(keys[0], keys[1]) {
		t.Fatal("separate generation reused a signing key")
	}
}

func TestPolicyAuthorInputErrorsLeaveNoOutput(t *testing.T) {
	for _, args := range [][]string{
		{"generate", "-ttl", "0"}, {"generate", "-ttl", "-1h"}, {"generate", "-ttl", "366d"},
		{"generate", "-organization", "bad/name"}, {"generate", "-revision", "bad revision"},
		{"generate", "-profile", "bad/profile"}, {"generate", "extra"}, {"generate", "-mount", ""},
		{"generate", "-signing-key", "private.pem"}, {"sign"}, {"sign", "-ephemeral"},
		{"sign", "-data", "missing.json", "-ephemeral"},
		{"sign", "-data", "missing.json", "-signing-key", "key.pem", "-ephemeral"},
		{"sign", "-data", "missing.json"}, {"sign", "extra"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "new-parent", "policy")
			if code := CmdPolicy(append(args[:len(args):len(args)], "-out", out)); code == 0 {
				t.Fatalf("invalid arguments accepted: %v", args)
			}
			if _, err := os.Lstat(filepath.Dir(out)); !os.IsNotExist(err) {
				t.Fatalf("invalid authoring created output/parent: %v", err)
			}
		})
	}
	for _, op := range []string{"generate", "sign"} {
		if code := CmdPolicy([]string{op, "-help"}); code != 0 {
			t.Fatalf("%s help exit = %d", op, code)
		}
	}
	file := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{file, file + "-missing"} {
		if _, err := canonicalPolicyMount(path); err == nil {
			t.Fatal("non-directory mount accepted")
		}
	}
}

func TestPolicyTTL(t *testing.T) {
	for text, want := range map[string]time.Duration{"30d": 30 * 24 * time.Hour, "365d": 365 * 24 * time.Hour, "1s": time.Second, "1h30m": 90 * time.Minute} {
		if got, err := parsePolicyTTL(text); err != nil || got != want {
			t.Errorf("TTL %q = %v, %v", text, got, err)
		}
	}
	for _, text := range []string{"", "1.5d", "999999999999999999999999d", "NaNd", "-30d", "0d", "500ms", "8761h", "9999999999999999999h"} {
		if _, err := parsePolicyTTL(text); err == nil {
			t.Errorf("invalid TTL %q accepted", text)
		}
	}
}

func TestPolicyCanonicalMountAndOutputSymlinks(t *testing.T) {
	root := t.TempDir()
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(root, alias); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	got, err := canonicalPolicyMount(alias)
	want, wantErr := filepath.EvalSymlinks(root)
	if err != nil || wantErr != nil || got != want {
		t.Fatalf("mount not canonical: %q, %v", got, err)
	}
	if _, err := newPolicyOutputPath(alias); err == nil {
		t.Fatal("symlink output accepted")
	}
	if err := os.RemoveAll(root); err != nil {
		t.Fatal(err)
	}
	if _, err := newPolicyOutputPath(alias); err == nil {
		t.Fatal("dangling symlink output accepted")
	}
}

func TestPolicySignExistingKeyAndEphemeral(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	keyPath := filepath.Join(base, "private.pem")
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	doc := policy.Document{Version: 1, Organization: "org", Revision: "edited-2", ExpiresAt: time.Now().UTC().Add(time.Hour), Profiles: map[string]policy.Profile{
		"dev": {Rules: []policy.Rule{{ID: "read", Effect: "allow", Action: policy.MCPCall, Server: "fs", Tool: "read_file"}}},
	}}
	data, err := policy.MarshalDocument(doc)
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(base, "data.json")
	if err := os.WriteFile(source, data, 0o600); err != nil {
		t.Fatal(err)
	}
	var previousPublic string
	for _, mode := range []string{"existing", "ephemeral"} {
		out := filepath.Join(base, mode)
		args := []string{"sign", "-data", source, "-out", out}
		if mode == "existing" {
			args = append(args, "-signing-key", keyPath)
		} else {
			args = append(args, "-ephemeral")
		}
		if code := CmdPolicy(args); code != 0 {
			t.Fatalf("sign %s exit = %d", mode, code)
		}
		c, engine := readAuthoredPolicy(t, out, "dev")
		if d := engine.Evaluate(context.Background(), policy.MCPCall, policy.Resource{Server: "fs", Tool: "read_file"}); d.Effect != "allow" || d.Revision != "edited-2" {
			t.Fatalf("signing changed policy: %+v", d)
		}
		if !engine.ExpiresAt().Equal(doc.ExpiresAt) {
			t.Fatal("sign implicitly changed TTL")
		}
		if mode == "existing" {
			block, _ := pem.Decode([]byte(c.PublicKey))
			parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil || parsed.(*rsa.PublicKey).N.Cmp(key.N) != 0 {
				t.Fatal("supplied signing key not used")
			}
			previousPublic = c.PublicKey
		} else if previousPublic == c.PublicKey {
			t.Fatal("ephemeral sign reused an existing key")
		}
		if code := CmdPolicy(args); code == 0 {
			t.Fatal("sign overwrote existing output")
		}
	}
	after, err := os.ReadFile(keyPath)
	if err != nil || !bytes.Equal(after, keyPEM) {
		t.Fatal("private key file modified")
	}
	after, err = os.ReadFile(source)
	if err != nil || !bytes.Equal(after, data) {
		t.Fatal("source file modified")
	}
	badOutput := filepath.Join(base, "bad")
	if err := os.WriteFile(source, []byte(`{"gantry":{"unknown":true}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := CmdPolicy([]string{"sign", "-data", source, "-out", badOutput, "-signing-key", keyPath}); code == 0 {
		t.Fatal("invalid source signed")
	}
	if _, err := os.Lstat(badOutput); !os.IsNotExist(err) {
		t.Fatal("invalid source created output")
	}
}

func TestPolicyOutputConcurrentWritersDoNotMix(t *testing.T) {
	out := filepath.Join(t.TempDir(), "policy")
	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for _, marker := range []string{"first", "second"} {
		wg.Go(func() {
			<-start
			data := []byte(marker)
			results <- writePolicyOutput(out, policy.SignedDocument{Data: data, Bundle: data, PublicKey: data})
		})
	}
	close(start)
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("successful writers = %d", successes)
	}
	var first []byte
	for _, name := range []string{"source/data.json", "bundle.tar.gz", "public.pem"} {
		raw, err := os.ReadFile(filepath.Join(out, filepath.FromSlash(name)))
		if err != nil {
			t.Fatal(err)
		}
		if first == nil {
			first = raw
		} else if !bytes.Equal(first, raw) {
			t.Fatal("mixed output generations")
		}
	}
}

func TestPolicyKeygenCreatesAStableSigningKeyOnce(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "acme-key")
	if code := CmdPolicy([]string{"keygen", "-out", dir, "-bits", "2048"}); code != 0 {
		t.Fatalf("keygen exit = %d", code)
	}
	info, err := os.Stat(filepath.Join(dir, "signing-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("signing key mode = %v", info.Mode().Perm())
	}
	key, err := policy.ReadSigningKey(filepath.Join(dir, "signing-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	document := policy.Document{Version: 1, Organization: "acme", Revision: "r1", ExpiresAt: time.Now().Add(time.Hour),
		Profiles: map[string]policy.Profile{"developer": {}}}
	signed, err := policy.SignDocument(document, key)
	if err != nil {
		t.Fatal(err)
	}
	public, err := os.ReadFile(filepath.Join(dir, "public.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policy.VerifyBundle(signed.Bundle, string(public)); err != nil {
		t.Fatalf("bundle signed with the generated key does not verify with its public key: %v", err)
	}
	if code := CmdPolicy([]string{"keygen", "-out", dir}); code == 0 {
		t.Fatal("keygen overwrote an existing directory")
	}
}
