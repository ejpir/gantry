package manifest

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ejpir/gantry/internal/oauthprovider"
	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/secret"
)

func TestDecodeCompilesManifestIntoRunOptions(t *testing.T) {
	base := t.TempDir()
	raw := `apiVersion: gantry.dev/v1alpha1
kind: Sandbox
metadata:
  name: dev
spec:
  image: debian:bookworm-slim
  runtime: crun
  resources:
    cpus: 2
    memory: 2GiB
    disk: 4GiB
  root:
    writable: true
  shares:
    - name: source
      source: ./src
      target: /workspace
      readOnly: true
      uid: 1000
      gid: 1000
  network:
    enabled: true
    allowLocal: true
    policy: ./network.json
    ports:
      - host: 127.0.0.1:8080
        guest: 80
        protocol: tcp
    proxy:
      url: http://proxy.example:3128
      noProxy: [localhost, 127.0.0.1]
      enforce: true
  secrets:
    - name: GITHUB_TOKEN
      environment: GITHUB_TOKEN
      bind: github.com
    - name: NPM_TOKEN
      file: ./secrets/npm
      ttl: 1m
  ssh:
    enabled: true
  devContainers:
    enabled: true
  processIsolation: required
`
	compiled, err := Decode(strings.NewReader(raw), base)
	if err != nil {
		t.Fatal(err)
	}
	options := compiled.Options
	if options.Name != "dev" || options.Image != "debian:bookworm-slim" || options.Runtime != "crun" {
		t.Fatalf("identity options = %+v", options)
	}
	if options.MemMB != 2048 || options.VCPUs != 2 || options.RWLayerSizeMiB != 4096 {
		t.Fatalf("resources = memory %d, cpus %d, disk %d", options.MemMB, options.VCPUs, options.RWLayerSizeMiB)
	}
	if !options.Explicit.Memory || !options.Explicit.CPUs || !options.Explicit.DiskSize || !options.Explicit.RW || !options.RW {
		t.Fatalf("explicit options = %+v, rw=%v", options.Explicit, options.RW)
	}
	sharePath := filepath.Join(base, "src")
	if len(options.Shares) != 1 || !strings.Contains(options.Shares[0], sharePath) {
		t.Fatalf("shares = %q", options.Shares)
	}
	if options.NetPol != filepath.Join(base, "network.json") || len(options.Publish) != 1 || options.Publish[0] != "127.0.0.1:8080:80" {
		t.Fatalf("network options = policy %q, ports %q", options.NetPol, options.Publish)
	}
	if got := options.Secrets; len(got) != 2 || got[0] != "GITHUB_TOKEN@github.com" || got[1] != "NPM_TOKEN=@"+filepath.Join(base, "secrets", "npm")+",ttl=1m0s" {
		t.Fatalf("secrets = %q", got)
	}
	if !options.SSH || !options.DevContainers || options.ProcessIsolation != "required" {
		t.Fatalf("service options = %+v", options)
	}
	if options.Manifest == nil || !strings.HasPrefix(options.Manifest.Digest, "sha256:") || options.Manifest.APIVersion != APIVersion {
		t.Fatalf("manifest provenance = %+v", options.Manifest)
	}
}

func TestDecodeIsStrict(t *testing.T) {
	validPrefix := "apiVersion: gantry.dev/v1alpha1\nkind: Sandbox\nmetadata:\n  name: dev\nspec:\n"
	for name, raw := range map[string]string{
		"unknown":   validPrefix + "  typo: true\n",
		"duplicate": validPrefix + "  image: alpine:latest\n  image: debian:bookworm\n",
		"alias":     validPrefix + "  image: &image alpine:latest\n  runtime: *image\n",
		"documents": validPrefix + "  image: alpine:latest\n---\n" + validPrefix,
		"literal":   validPrefix + "  secrets:\n    - name: TOKEN\n      value: exposed\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode(strings.NewReader(raw), t.TempDir()); err == nil {
				t.Fatalf("Decode accepted invalid manifest:\n%s", raw)
			}
		})
	}
}

func TestCompileRejectsInvalidSemanticFields(t *testing.T) {
	base := func(spec string) string {
		return "apiVersion: gantry.dev/v1alpha1\nkind: Sandbox\nmetadata:\n  name: dev\nspec:\n" + spec
	}
	for name, raw := range map[string]string{
		"memory unit":       base("  resources:\n    memory: 2000\n"),
		"secret rename":     base("  secrets:\n    - name: TOKEN\n      environment: OTHER\n"),
		"secret sources":    base("  secrets:\n    - name: TOKEN\n      environment: TOKEN\n      file: token\n"),
		"port protocol":     base("  network:\n    ports:\n      - guest: 80\n        protocol: sctp\n"),
		"disabled network":  base("  network:\n    enabled: false\n    ports:\n      - guest: 80\n"),
		"devcontainers ssh": base("  devContainers:\n    enabled: true\n"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode(strings.NewReader(raw), t.TempDir()); err == nil {
				t.Fatalf("Decode accepted invalid manifest:\n%s", raw)
			}
		})
	}
}

func TestCompileKeepsEphemeralPortsUnallocatedUntilApply(t *testing.T) {
	raw := `apiVersion: gantry.dev/v1alpha1
kind: Sandbox
metadata: {name: dev}
spec:
  network:
    ports:
      - guest: 8080
`
	first, err := Decode(strings.NewReader(raw), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	second, err := Decode(strings.NewReader(raw), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Options.Publish) != 1 || first.Options.Publish[0] != "8080" {
		t.Fatalf("ephemeral port was resolved during validation: %q", first.Options.Publish)
	}
	if first.Options.Manifest.Digest != second.Options.Manifest.Digest {
		t.Fatal("identical ephemeral-port manifests produced different digests")
	}
}

func TestManifestDigestIsNormalizedToManifestDirectory(t *testing.T) {
	raw := `apiVersion: gantry.dev/v1alpha1
kind: Sandbox
metadata: {name: dev}
spec:
  shares:
    - name: source
      source: ./src
`
	first, err := Decode(strings.NewReader(raw), filepath.Join(t.TempDir(), "a"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := Decode(strings.NewReader(raw), filepath.Join(t.TempDir(), "b"))
	if err != nil {
		t.Fatal(err)
	}
	if first.Options.Manifest.Digest == second.Options.Manifest.Digest {
		t.Fatal("manifests with different resolved host paths have the same digest")
	}
}

func TestFromConfigExportsRedactedReapplicableManifest(t *testing.T) {
	bridge, custody := true, true
	cfg := config.RunConfig{
		Kernel: "/assets/kernel", KernelPolicy: config.KernelPolicyPinned,
		Rootfs: "/assets/rootfs.erofs", ImageRef: "alpine:latest", Image: "/cache/image.erofs",
		RWLayer: "/state/dev.ext4", RWLayerSizeMiB: 2048, RW: true,
		Shares: []string{"source=/work,ro,mount=/workspace"}, Ports: []string{"127.0.0.1:8080:80"},
		Net: true, NetPol: "/policies/net.json", MemMB: 1024, VCPUs: 2,
		Runtime: "crun", ProcessIsolation: "required", SSH: true,
		OAuthBridge: &bridge, OAuthCustody: &custody,
		OAuthProviders: []oauthprovider.Spec{{Provider: "example", Grant: oauthprovider.AuthorizationCode, AuthorizeURL: "https://id.example/authorize", TokenURL: "https://id.example/token", ClientID: "public", RedirectURI: "http://127.0.0.1:0/callback"}},
		SecretNames:    []string{"TOKEN", "FILE_TOKEN@example.com=@/run/token,ttl=1m0s"},
		SecretSources:  []secret.NamedSource{{Name: "FILE_TOKEN", Source: secret.Source{Kind: secret.SourceFile, Ref: "/run/token", Binding: "example.com", Refresh: timeMinute}}},
	}
	document, err := FromConfig("dev", cfg)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("secret-value")) || !bytes.Contains(raw, []byte("environment: TOKEN")) || !bytes.Contains(raw, []byte("file: /run/token")) {
		t.Fatalf("unexpected redacted manifest:\n%s", raw)
	}
	compiled, err := Decode(bytes.NewReader(raw), t.TempDir())
	if err != nil {
		t.Fatalf("exported manifest is not reapplicable: %v\n%s", err, raw)
	}
	if compiled.Options.Image != "alpine:latest" || len(compiled.Options.Secrets) != 2 || len(compiled.Options.OAuthProviders) != 1 {
		t.Fatalf("compiled export = %+v", compiled.Options)
	}
}

const timeMinute = 60 * 1e9
