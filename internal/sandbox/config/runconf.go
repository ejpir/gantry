package config

// runconf.go — the single option-resolution path shared by all three VM
// entry points (`gantry exec`, `gantry start`, `gantry daemon`).
//
// Historically each entry point carried its own ~60-line copy of the
// runtime switch, image/rwlayer defaults, -rw rules, share parsing and
// network/policy construction; they drifted (start once produced VMs
// whose rwlayer the guest was told to mount but the daemon never
// attached). RunConfig is the one resolved shape — and, serialized as
// sandbox.json, the identity of a sandbox.

import (
	"flag"
	"fmt"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/ejpir/gantry/internal/client"
	"github.com/ejpir/gantry/internal/guestasset"
	"github.com/ejpir/gantry/internal/gutil"
	"github.com/ejpir/gantry/internal/image"
	"github.com/ejpir/gantry/internal/secret"
	"github.com/ejpir/gantry/internal/shares"
)

// MCPRestartMarker records that persisted MCP settings differ from the live,
// immutable MCP worker. A successful daemon restart removes it.
const MCPRestartMarker = "mcp-restart-required"

// RunConfig is the fully-resolved description of one gantry VM run.
// sandbox.json is this struct.
type RunConfig struct {
	Kernel string `json:"kernel"`
	// KernelPolicy records whether Kernel follows Gantry releases or was
	// explicitly selected by the user. Release-managed kernels are refreshed
	// when a stopped sandbox is started by a newer Gantry binary; pinned
	// kernels are never replaced. Empty is reserved for legacy configs and is
	// migrated conservatively at the next restart.
	KernelPolicy string `json:"kernel_policy,omitempty"`
	Rootfs       string `json:"rootfs"`
	// GuestTools is the resolved absolute path of the multicall guest
	// helper binary (gantry-guest-<arch>), recorded when host-bound
	// secrets require it. Persisted because the daemon runs with cwd "/",
	// where the development-tree relative asset lookup cannot find it.
	GuestTools string `json:"guest_tools,omitempty"`
	Runtime    string `json:"runtime,omitempty"`
	Image      string `json:"image"`
	// ImageRef/ImageDigest/ImageCfg record an OCI image resolution
	// (-image given a reference, OCI layout, or docker save tar instead
	// of a plain .erofs file). The daemon uses the already-built EROFS at
	// Image; it never pulls. ImageCfg feeds the session process spec.
	ImageRef    string        `json:"image_ref,omitempty"`
	ImageDigest string        `json:"image_digest,omitempty"`
	ImageCfg    *image.Config `json:"image_config,omitempty"`
	// LayerSet replaces the flattened Image with a native multi-device
	// EROFS set (containerd erofs-snapshotter layout: fsmeta + ordered
	// layer blobs), attached as-is — e.g. another stack's store. When
	// set, Image is empty and the guest mounts fsmeta with every layer
	// blob as a device= option.
	LayerSet       *client.LayerSet `json:"layerset,omitempty"`
	RWLayer        string           `json:"rwlayer,omitempty"`
	RWLayerSizeMiB uint             `json:"rwlayer_size_mib,omitempty"`
	RW             bool             `json:"rw"`
	Shares         []string         `json:"shares,omitempty"` // raw TAG=PATH[,ro] specs, absolute
	Ports          []string         `json:"ports,omitempty"`  // canonical IP:HOST:GUEST[/PROTO] publish specs
	Net            bool             `json:"net"`
	GVProxy        string           `json:"gvproxy,omitempty"`
	NetPol         string           `json:"net_policy,omitempty"`
	AllowLN        bool             `json:"allow_local_net,omitempty"`
	ProxyURL       string           `json:"proxy,omitempty"`
	NoProxy        string           `json:"no_proxy,omitempty"`
	ProxyEnforce   bool             `json:"proxy_enforce,omitempty"`
	// OAuthBridge controls the bounded host loopback callback bridge. Nil
	// means enabled, preserving the default for configs written before this
	// field existed; a non-nil false value is the persisted opt-out.
	OAuthBridge *bool `json:"oauth_bridge,omitempty"`
	// OAuthCustody moves OAuth token custody host-side (workstream 3):
	// the daemon exchanges codes itself, holds refresh tokens, and pushes
	// fresh access tokens into the guest auth file. Default off — the
	// transparent bridge needs no provider-specific knowledge.
	OAuthCustody *bool `json:"oauth_custody,omitempty"`
	// MCP gates the per-sandbox split MCP gateway (docs/mcp-gateway.md): a
	// capability-limited host worker reached through a vsock/opaque-relay
	// mux, with contained local servers. MCPFSRoot jails the built-in filesystem server; MCPFSUser
	// is the unprivileged guest user local servers drop to.
	MCP       bool   `json:"mcp,omitempty"`
	MCPFSRoot string `json:"mcp_fs_root,omitempty"`
	MCPFSUser string `json:"mcp_fs_user,omitempty"`
	// MCPRemotes are -mcp-remote specs: comma-separated k=v with keys
	// name, url, auth (bearer:SECRET | header:NAME:SECRET |
	// custody:PROVIDER), allow/deny (repeated globs), redact (repeated
	// secret names). Parsed at resolve time into immutable worker metadata
	// plus supervisor-owned capability mappings.
	MCPRemotes []string `json:"mcp_remotes,omitempty"`
	// SSH enables the per-sandbox local SSH protocol endpoint. It is opt-in;
	// no ssh.sock exists when false.
	SSH bool `json:"ssh,omitempty"`
	// DevContainers enables the explicit nested-container OCI profile. It
	// exposes no host container engine; inner runtimes remain inside this VM.
	DevContainers bool `json:"devcontainers,omitempty"`
	MemMB         uint `json:"memMB"`
	VCPUs         int  `json:"vcpus,omitempty"`
	// SecretNames records WHICH secrets the sandbox injects. Names only:
	// the values live in the daemon's memory for the VM's lifetime and
	// are never written anywhere (docs/secrets.md rule 1). Source-backed
	// secrets persist as their full spec (NAME[@host][=@path][,ttl=...])
	// so resume can rebuild the daemon-side Store; the spec contains refs
	// (paths, env names), never values.
	SecretNames []string `json:"secret_names,omitempty"`
	// SecretSources are the daemon-resolved sources for -secret specs.
	// Literal -secret-file values are not sources and never persist.
	SecretSources []secret.NamedSource `json:"secret_sources,omitempty"`
	// ProcessIsolation selects the supervisor/worker topology
	// (docs/vmm-network-isolation.md): "auto" (strongest available,
	// currently the split network worker on Unix), "required" (fail
	// startup unless the split is established), "off" (monolithic).
	// Empty behaves as auto, so pre-existing sandbox configs upgrade.
	ProcessIsolation string `json:"process_isolation,omitempty"`
}

// RunFlags holds the CLI flag pointers shared by `gantry exec` and
// `gantry start`. Register them on the FlagSet, parse, then Resolve.
type RunFlags struct {
	// Name is the sandbox name (set by `gantry start` before Resolve;
	// empty for one-shot exec). It selects the per-sandbox rwlayer
	// default: ~/.gantry/rwlayers/<name>.ext4 instead of the shared
	// ./rwlayer.ext4 — a shared writable default was the corruption
	// vector behind the ESTALE saga (two live VMs on one ext4).
	Name                                    string
	Kernel, Rootfs, Runtime, Image, RWLayer *string
	LayerSet                                *string
	RWLayerSizeMiB                          *uint
	RW                                      *bool
	Shares                                  *gutil.StrList
	Publish                                 *gutil.StrList
	Net                                     *bool
	GVProxy, NetPol                         *string
	AllowLN                                 *bool
	ProxyURL, NoProxy                       *string
	ProxyEnforce                            *bool
	OAuthBridge                             *bool
	OAuthCustody                            *bool
	MCP                                     *bool
	MCPFSRoot, MCPFSUser                    *string
	MCPRemotes                              *gutil.StrList
	SSH, DevContainers                      *bool
	ProcessIsolation                        *string
	MemMB                                   *uint
	VCPUs                                   *int
	Secrets, SecretFiles                    *gutil.StrList
}

// RegisterRunFlags adds the shared run flags to fs.
func RegisterRunFlags(fs *flag.FlagSet) *RunFlags {
	f := &RunFlags{
		Kernel: fs.String("kernel", guestasset.DefaultKernel(), "Linux kernel image (arm64 Image or x86-64 vmlinux ELF)"),
		Rootfs: fs.String("rootfs", guestasset.DefaultRootfs(), "VM rootfs (nerdbox EROFS with vminitd)"),
		Image: fs.String("image", "", `container image: a reference to pull ("debian:bookworm-slim",
"ghcr.io/org/app@sha256:..."), an OCI layout dir, a docker save tar,
or a plain .erofs file (default: release Alpine image; staged Debian/shell image in development)`),
		RWLayer:          fs.String("rwlayer", "", "ext4 writable layer, /dev/vdc (default: per-sandbox ~/.gantry/rwlayers/<name>.ext4, auto-created)"),
		RWLayerSizeMiB:   fs.Uint("disk-size", DefaultRWLayerSizeMiB, "persistent writable disk size in MiB (used only when creating the per-sandbox layer)"),
		LayerSet:         fs.String("layerset", "", "layerset manifest JSON (fsmeta + ordered layer blobs) to attach natively instead of a flattened image"),
		RW:               fs.Bool("rw", false, "writable overlay container root (default: on when a writable layer exists)"),
		Net:              fs.Bool("net", true, "attach virtio-net via the embedded netstack"),
		GVProxy:          fs.String("gvproxy", "", "use this external gvproxy binary instead of the embedded netstack"),
		NetPol:           fs.String("net-policy", "", "JSON egress policy file (rules + domain allowlist)"),
		AllowLN:          fs.Bool("allow-local-net", false, "let the sandbox reach LAN/link-local/host (default: internet only)"),
		ProxyURL:         fs.String("proxy", "", "route guest HTTP(S) through this http(s) or socks5(h) proxy URL"),
		NoProxy:          fs.String("no-proxy", "", "comma-separated proxy bypasses (default: localhost and loopback)"),
		ProxyEnforce:     fs.Bool("proxy-enforce", false, "block direct TCP 80/443 and UDP 443 except to the configured proxy"),
		OAuthBridge:      fs.Bool("oauth-bridge", true, "bridge agent OAuth loopback callbacks to bounded host listeners (disable with -oauth-bridge=false)"),
		OAuthCustody:     fs.Bool("oauth-custody", false, "hold OAuth refresh tokens on the host; push fresh access tokens into the guest (claude, codex)"),
		MCP:              fs.Bool("mcp", false, "run the per-sandbox MCP gateway (docs/mcp-gateway.md): agents reach it via gantry-guest mcp-proxy"),
		MCPFSRoot:        fs.String("mcp-fs-root", "/", "jail directory for the gateway's built-in filesystem server"),
		MCPFSUser:        fs.String("mcp-fs-user", "nobody", "unprivileged guest user or UID:GID the gateway's local servers run as"),
		MCPRemotes:       &gutil.StrList{},
		SSH:              fs.Bool("ssh", false, "enable SSH protocol access on the sandbox-local ssh.sock (no TCP listener)"),
		DevContainers:    fs.Bool("devcontainers", false, "enable nested Podman/Dev Containers inside this VM (requires -ssh and crun)"),
		ProcessIsolation: fs.String("process-isolation", "auto", "split sandbox into supervisor + worker processes: auto | required | off"),
		MemMB:            fs.Uint("mem", 512, "guest RAM in MiB"),
		VCPUs:            fs.Int("cpus", 1, fmt.Sprintf("guest vCPU count (max %d on this host)", MaxSandboxVCPUs())),
		Shares:           &gutil.StrList{},
		Publish:          &gutil.StrList{},
		Secrets:          &gutil.StrList{},
		SecretFiles:      &gutil.StrList{},
	}
	runtime := os.Getenv("GANTRY_RUNTIME")
	if runtime == "" {
		runtime = "crun"
	}
	f.Runtime = fs.String("runtime", runtime, "container runtime in the guest: crun | runsc (gVisor)")
	fs.Var(f.Shares, "share", "host directory exported through virtio-fs as TAG=PATH[,mount=CTRPATH][,ro][,uid=N,gid=N] (repeatable)")
	fs.Var(f.MCPRemotes, "mcp-remote", `remote MCP upstream: name=ID,url=https://HOST/PATH[,auth=bearer:SECRET|header:NAME:SECRET|custody:PROVIDER][,allow=GLOB][,deny=GLOB][,redact=SECRET] (repeatable)`)
	fs.Var(f.Publish, "p", "publish a guest port on the host: [IP:]HOST:GUEST[/udp], loopback by default (repeatable)")
	fs.Var(f.Publish, "publish", "alias for -p")
	fs.Var(f.Secrets, "secret", `inject a secret: NAME (from gantry's environment),
NAME=@/path (file), or NAME='!cmd args' (exec stdout); suffix NAME@host binds
to a host for broker-only delivery, ,ttl=60s overrides the refresh interval
(0 = on-demand). Repeatable. NAME=literal is refused`)
	fs.Var(f.SecretFiles, "secret-file", "dotenv-style file of NAME=VALUE secrets (repeatable)")
	return f
}

// OAuthBridgeEnabled resolves the default-on persisted setting. A pointer is
// used so configs written before oauth_bridge existed also inherit the default.
func (c RunConfig) OAuthBridgeEnabled() bool {
	return c.OAuthBridge == nil || *c.OAuthBridge
}

// OAuthCustodyEnabled resolves the default-off custody setting.
func (c RunConfig) OAuthCustodyEnabled() bool {
	return c.OAuthCustody != nil && *c.OAuthCustody
}

// NormalizeProcessIsolation resolves an unset persisted value to "auto": try
// to confine, degrading with a warning where the platform cannot.
func NormalizeProcessIsolation(mode string) string {
	if mode == "" {
		return "auto"
	}
	return mode
}

func ValidateProcessIsolation(mode string) error {
	switch NormalizeProcessIsolation(mode) {
	case "auto", "required", "off":
		return nil
	default:
		return fmt.Errorf("process isolation must be auto, required, or off, got %q", mode)
	}
}

// NormalizeMCPFilesystem validates and canonicalizes the built-in guest
// filesystem server settings. Guest paths are POSIX paths on every host.
func NormalizeMCPFilesystem(root, user string) (string, string, error) {
	if root == "" {
		root = "/"
	}
	if user == "" {
		user = "nobody"
	}
	user = strings.TrimSpace(user)
	if user == "" {
		return "", "", fmt.Errorf("-mcp-fs-user must not be empty (local MCP servers never run as root)")
	}
	uidText, gidText, numericPair := strings.Cut(user, ":")
	uid, numericUIDErr := strconv.ParseUint(uidText, 10, 32)
	if user == "root" || (numericUIDErr == nil && uid == 0) {
		return "", "", fmt.Errorf("-mcp-fs-user must not be root: local MCP servers run unprivileged (docs/mcp-gateway.md)")
	}
	if numericPair {
		if strings.Contains(gidText, ":") || numericUIDErr != nil {
			return "", "", fmt.Errorf("-mcp-fs-user numeric identity must be UID:GID, got %q", user)
		}
		if _, err := strconv.ParseUint(gidText, 10, 32); err != nil {
			return "", "", fmt.Errorf("-mcp-fs-user numeric identity must be UID:GID, got %q", user)
		}
	}
	if !path.IsAbs(root) {
		return "", "", fmt.Errorf("-mcp-fs-root must be an absolute guest path, got %q", root)
	}
	return path.Clean(root), user, nil
}

// ResolveSecrets parses -secret/-secret-file into the value map (CLI
// memory only — never serialized) plus the ordered unique names.
var osLookupEnv = os.LookupEnv

func (f *RunFlags) ResolveSecrets() (map[string]secret.Value, []string, error) {
	return secret.ResolveAll(f.Secrets.List(), f.SecretFiles.List(), osLookupEnv)
}

// ResolveSecretSources is the sandbox-start resolution path. Two kinds
// of secrets, two delivery contracts:
//
//   - ENV specs (NAME, NAME@host) resolve eagerly from the CLI's
//     environment, exactly like v1: the value rides the stdin handshake
//     and scrubbedEnv keeps it out of the daemon's /proc/environ. Env
//     vars are static for a process's lifetime — a TTL would buy nothing.
//   - FILE/EXEC specs (NAME=@path, NAME=!argv) become daemon-resolved
//     SOURCES: the CLI never holds their values, and the daemon's Store
//     re-resolves them at use time so rotation is picked up live.
//
// -secret-file entries stay literal values (dotenv files carry values,
// not sources). Returns the literal values, the named file/exec sources,
// and the ordered unique persisted specs. Later occurrences of a name win
// across all kinds.
func (f *RunFlags) ResolveSecretSources() (map[string]secret.Value, []secret.NamedSource, []string, error) {
	values := map[string]secret.Value{}
	sources := map[string]secret.NamedSource{}
	display := map[string]string{}
	var order []string
	add := func(name, spec string) {
		if _, seen := display[name]; !seen {
			order = append(order, name)
		}
		display[name] = spec
	}
	for _, file := range f.SecretFiles.List() {
		m, err := secret.ParseFile(file)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("-secret-file: %w", err)
		}
		for _, name := range sortedNames(m) {
			values[name] = m[name]
			delete(sources, name)
			add(name, name)
		}
	}
	for _, spec := range f.Secrets.List() {
		ns, err := secret.ParseNamedSource(spec)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("-secret: %w", err)
		}
		if ns.Source.Kind == secret.SourceEnv {
			// ParseSpec on an env spec is exactly the v1 path: eager value,
			// unset-var error, literal refusal, binding validation.
			s, err := secret.ParseSpec(spec, osLookupEnv)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("-secret: %w", err)
			}
			values[s.Name] = s.Value
			delete(sources, s.Name)
			add(s.Name, s.DisplayName())
			continue
		}
		sources[ns.Name] = ns
		delete(values, ns.Name)
		add(ns.Name, ns.Spec())
	}
	names := make([]string, 0, len(order))
	ordered := make([]secret.NamedSource, 0, len(sources))
	for _, n := range order {
		names = append(names, display[n])
		if ns, ok := sources[n]; ok {
			ordered = append(ordered, ns)
		}
	}
	return values, ordered, names, nil
}

func sortedNames(m map[string]secret.Value) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ParsedShares validates cfg.Shares into virtio-fs share descriptors.
func (c RunConfig) ParsedShares() ([]shares.Spec, error) {
	return shares.ParseSpecs(c.Shares)
}

// Writable-layer size bounds. They are configuration limits rather than
// allocator details: the -disk-size flag, sandbox.json validation and the
// dashboard's advertised range all read them from here.
const (
	DefaultRWLayerSizeMiB = 512
	MinRWLayerSizeMiB     = 512
	MaxRWLayerSizeMiB     = 64 << 10

	// Dev Containers need room for an editor server, image layers, and builds.
	// These replace ordinary defaults only when the corresponding start flag
	// was not explicitly supplied.
	DefaultDevContainersMemoryMiB   = 4 << 10
	DefaultDevContainersVCPUs       = 4
	DefaultDevContainersDiskSizeMiB = 32 << 10
)

func ValidateRWLayerSize(sizeMiB uint) error {
	if sizeMiB < MinRWLayerSizeMiB || sizeMiB > MaxRWLayerSizeMiB {
		return fmt.Errorf("-disk-size must be between %d and %d MiB, got %d", MinRWLayerSizeMiB, MaxRWLayerSizeMiB, sizeMiB)
	}
	return nil
}

// KernelPolicy values. "release" tracks the kernel shipped with the current
// gantry release across restarts; "pinned" keeps whatever the sandbox was
// created with.
const (
	KernelPolicyRelease = "release"
	KernelPolicyPinned  = "pinned"
)
