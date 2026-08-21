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

	"github.com/ejpir/gantry/internal/client"
	"github.com/ejpir/gantry/internal/guestasset"
	"github.com/ejpir/gantry/internal/gutil"
	"github.com/ejpir/gantry/internal/image"
	"github.com/ejpir/gantry/internal/secret"
	"github.com/ejpir/gantry/internal/shares"
)

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
	MemMB       uint  `json:"memMB"`
	VCPUs       int   `json:"vcpus,omitempty"`
	// SecretNames records WHICH secrets the sandbox injects. Names only:
	// the values live in the daemon's memory for the VM's lifetime and
	// are never written anywhere (docs/secrets.md rule 1).
	SecretNames []string `json:"secret_names,omitempty"`
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
	fs.Var(f.Shares, "share", "host directory exported through virtio-fs as TAG=PATH[@CTRPATH][,ro][,uid=N,gid=N] (repeatable)")
	fs.Var(f.Publish, "p", "publish a guest port on the host: [IP:]HOST:GUEST[/udp], loopback by default (repeatable)")
	fs.Var(f.Publish, "publish", "alias for -p")
	fs.Var(f.Secrets, "secret", `inject a secret into every session: NAME (from gantry's
environment) or NAME=@/path; repeatable. NAME=literal is refused`)
	fs.Var(f.SecretFiles, "secret-file", "dotenv-style file of NAME=VALUE secrets (repeatable)")
	return f
}

// OAuthBridgeEnabled resolves the default-on persisted setting. A pointer is
// used so configs written before oauth_bridge existed also inherit the default.
func (c RunConfig) OAuthBridgeEnabled() bool {
	return c.OAuthBridge == nil || *c.OAuthBridge
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

// ResolveSecrets parses -secret/-secret-file into the value map (CLI
// memory only — never serialized) plus the ordered unique names.
var osLookupEnv = os.LookupEnv

func (f *RunFlags) ResolveSecrets() (map[string]secret.Value, []string, error) {
	return secret.ResolveAll(f.Secrets.List(), f.SecretFiles.List(), osLookupEnv)
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
