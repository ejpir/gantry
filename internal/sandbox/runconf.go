package sandbox

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
	"github.com/ejpir/gantry/internal/client"
	"github.com/ejpir/gantry/internal/gutil"
	"github.com/ejpir/gantry/internal/image"
	"github.com/ejpir/gantry/internal/netpol"
	"github.com/ejpir/gantry/internal/secret"
	"github.com/ejpir/gantry/internal/vmm"
	"github.com/ejpir/gantry/internal/vnet"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// RunConfig is the fully-resolved description of one gantry VM run.
// sandbox.json is this struct.
type RunConfig struct {
	Kernel  string `json:"kernel"`
	Rootfs  string `json:"rootfs"`
	Runtime string `json:"runtime,omitempty"`
	Image   string `json:"image"`
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
	LayerSet *client.LayerSet `json:"layerset,omitempty"`
	RWLayer  string           `json:"rwlayer,omitempty"`
	RW       bool             `json:"rw"`
	Shares   []string         `json:"shares,omitempty"` // raw TAG=PATH[,ro] specs, absolute
	Ports    []string         `json:"ports,omitempty"`  // canonical IP:HOST:GUEST[/PROTO] publish specs
	Net      bool             `json:"net"`
	GVProxy  string           `json:"gvproxy,omitempty"`
	NetPol   string           `json:"net_policy,omitempty"`
	AllowLN  bool             `json:"allow_local_net,omitempty"`
	MemMB    uint             `json:"memMB"`
	VCPUs    int              `json:"vcpus,omitempty"`
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
	RW                                      *bool
	Shares                                  *gutil.StrList
	Publish                                 *gutil.StrList
	Net                                     *bool
	GVProxy, NetPol                         *string
	AllowLN                                 *bool
	ProcessIsolation                        *string
	MemMB                                   *uint
	VCPUs                                   *int
	Secrets, SecretFiles                    *gutil.StrList
}

// RegisterRunFlags adds the shared run flags to fs.
func RegisterRunFlags(fs *flag.FlagSet) *RunFlags {
	f := &RunFlags{
		Kernel: fs.String("kernel", vmm.DefaultKernelImage(), "Linux kernel image (arm64 Image or x86-64 vmlinux ELF)"),
		Rootfs: fs.String("rootfs", vmm.DefaultRootfs(), "VM rootfs (nerdbox EROFS with vminitd)"),
		Image: fs.String("image", "", `container image: a reference to pull ("debian:bookworm-slim",
"ghcr.io/org/app@sha256:..."), an OCI layout dir, a docker save tar,
or a plain .erofs file (default: artifacts/debian-bookworm.erofs if present)`),
		RWLayer:          fs.String("rwlayer", "", "ext4 writable layer, /dev/vdc (default: per-sandbox ~/.gantry/rwlayers/<name>.ext4, auto-created)"),
		LayerSet:         fs.String("layerset", "", "layerset manifest JSON (fsmeta + ordered layer blobs) to attach natively instead of a flattened image"),
		RW:               fs.Bool("rw", false, "writable overlay container root (default: on when a writable layer exists)"),
		Net:              fs.Bool("net", true, "attach virtio-net via the embedded netstack"),
		GVProxy:          fs.String("gvproxy", "", "use this external gvproxy binary instead of the embedded netstack"),
		NetPol:           fs.String("net-policy", "", "JSON egress policy file (rules + domain allowlist)"),
		AllowLN:          fs.Bool("allow-local-net", false, "let the sandbox reach LAN/link-local/host (default: internet only)"),
		ProcessIsolation: fs.String("process-isolation", "auto", "split sandbox into supervisor + worker processes: auto | required | off"),
		MemMB:            fs.Uint("mem", 512, "guest RAM in MiB"),
		VCPUs:            fs.Int("cpus", 1, "guest vCPU count (max 8)"),
		Shares:           &gutil.StrList{},
		Publish:          &gutil.StrList{},
		Secrets:          &gutil.StrList{},
		SecretFiles:      &gutil.StrList{},
	}
	f.Runtime = fs.String("runtime", func() string {
		if v := gutil.EnvOr("GANTRY_RUNTIME", "MINIVM_RUNTIME"); v != "" {
			return v
		}
		return "crun"
	}(), "container runtime in the guest: crun | runsc (gVisor)")
	fs.Var(f.Shares, "share", "host directory exported through virtio-fs as TAG=PATH[@CTRPATH][,ro][,uid=N,gid=N] (repeatable)")
	fs.Var(f.Publish, "p", "publish a guest port on the host: [IP:]HOST:GUEST[/udp], loopback by default (repeatable)")
	fs.Var(f.Publish, "publish", "alias for -p")
	fs.Var(f.Secrets, "secret", `inject a secret into every session: NAME (from gantry's
environment) or NAME=@/path; repeatable. NAME=literal is refused`)
	fs.Var(f.SecretFiles, "secret-file", "dotenv-style file of NAME=VALUE secrets (repeatable)")
	return f
}

// Resolve turns parsed flags into an absolute, fully-defaulted RunConfig.
// warnings are non-fatal degradations the caller surfaces at the end;
// progress (may be nil) fires in real time — registry pulls and image
// builds take seconds, and the user should watch them happen, not read
// them flushed at the end.
func (f *RunFlags) Resolve(fs *flag.FlagSet, progress func(string, ...any)) (cfg RunConfig, warnings []string, err error) {
	say := func(format string, a ...any) {
		if progress != nil {
			progress(format, a...)
		}
	}
	set := map[string]bool{}
	fs.Visit(func(fl *flag.Flag) { set[fl.Name] = true })

	cfg.Runtime = *f.Runtime
	cfg.Kernel, cfg.Rootfs = *f.Kernel, *f.Rootfs
	switch cfg.Runtime {
	case "crun":
	case "runsc":
		if !set["rootfs"] {
			cfg.Rootfs = vmm.GvisorRootfs(cfg.Rootfs)
		}
		if !set["kernel"] {
			cfg.Kernel = vmm.GvisorKernel(cfg.Kernel)
		}
		// No existence check here: the mapped gVisor rootfs is a
		// whitelisted release asset, so the generic rootfs resolution
		// below downloads it on first use, exactly like the default
		// rootfs. An explicit -rootfs still hard-errors when missing.
	default:
		return cfg, nil, fmt.Errorf("-runtime must be crun or runsc, got %q", cfg.Runtime)
	}

	// Kernel resolution: a default kernel that is not staged yet is
	// downloaded from the release page (gantry-kernel-* assets only, so
	// this never fires for user-supplied or nerdbox paths); an explicit
	// -kernel that is missing is a hard error.
	if cfg.Kernel != "" && !gutil.FileExists(cfg.Kernel) {
		if set["kernel"] {
			return cfg, nil, fmt.Errorf("kernel %s not found", cfg.Kernel)
		}
		k, err := vmm.EnsureKernel(cfg.Kernel, say)
		if err != nil {
			hint := "build it with ./scripts/mkkernel.sh"
			if cfg.Runtime == "runsc" {
				hint = "gVisor needs the 4K-page kernel: PAGES=4k ./scripts/mkkernel.sh"
			}
			return cfg, nil, fmt.Errorf("%w (%s)", err, hint)
		}
		cfg.Kernel = k
	}

	// Rootfs resolution: a default rootfs that is not staged yet is
	// downloaded from the release page (whitelisted nerdbox-rootfs*
	// assets only — including the gVisor variant -runtime runsc maps
	// to — so this never fires for user-supplied paths); an explicit
	// -rootfs that is missing is a hard error.
	if cfg.Rootfs != "" && !gutil.FileExists(cfg.Rootfs) {
		if set["rootfs"] {
			return cfg, nil, fmt.Errorf("rootfs %s not found", cfg.Rootfs)
		}
		r, err := vmm.EnsureRootfs(cfg.Rootfs, say)
		if err != nil {
			hint := "copy nerdbox-rootfs-<arch>.erofs from a nerdbox release into artifacts/, or build from source"
			if cfg.Runtime == "runsc" {
				hint = "or build it locally with ./scripts/mkrootfs-gvisor.sh " + vmm.DefaultRootfs()
			}
			return cfg, nil, fmt.Errorf("%w (%s)", err, hint)
		}
		cfg.Rootfs = r
	}

	cfg.Image = *f.Image
	if cfg.Image == "" {
		cfg.Image = vmm.DefaultImage()
	}
	if *f.LayerSet != "" {
		ls, err := client.LoadLayerSet(*f.LayerSet)
		if err != nil {
			return cfg, nil, err
		}
		if err := ls.Validate(); err != nil {
			return cfg, nil, err
		}
		cfg.LayerSet = ls
	}
	// Image resolution: an existing .erofs file is used as-is; anything
	// else (OCI layout dir, docker save tar, image reference) goes
	// through the image store, platform-matched to the GUEST kernel.
	// A layerset replaces the flattened image entirely.
	if cfg.LayerSet == nil && !isErofsFile(cfg.Image) {
		arch, err := vmm.KernelArch(cfg.Kernel)
		if err != nil {
			return cfg, nil, err
		}
		r, err := image.Resolve(cfg.Image, arch, nil, say)
		if err != nil {
			return cfg, nil, err
		}
		if r.Config != nil {
			cfg.ImageRef, cfg.ImageDigest, cfg.ImageCfg = r.Ref, r.Digest, r.Config
		}
		cfg.Image = r.Path
	}
	cfg.RWLayer = *f.RWLayer
	explicitRWLayer := cfg.RWLayer != ""
	if cfg.RWLayer == "" && f.Name != "" {
		// per-sandbox default, created on demand (see rwlayer.go);
		// an empty/absent file just means read-only below
		p, w, err := defaultRWLayer(f.Name, cfg.imageIdentity())
		if err != nil {
			return cfg, nil, err
		}
		warnings = append(warnings, w...)
		cfg.RWLayer = p
	} else if cfg.RWLayer == "" && gutil.FileExists(vmm.AssetPath("rwlayer.ext4")) {
		// one-shot exec: legacy shared default, flock-guarded by the
		// blk device and pairing-checked like everything else
		cfg.RWLayer = vmm.AssetPath("rwlayer.ext4")
		explicitRWLayer = true // user-owned file: no pairing enforcement
	}
	// -rw rules: default on when a writable layer exists, forced off when
	// none does — never hand the guest RW=true for a disk we didn't attach.
	// A layerset IS the overlay pair: the rwlayer is mandatory and RW is
	// always on.
	if cfg.LayerSet != nil {
		if set["rw"] && !*f.RW {
			return cfg, nil, fmt.Errorf("a layerset is a writable overlay pair (remove -rw=false)")
		}
		if cfg.RWLayer == "" {
			return cfg, nil, fmt.Errorf("a layerset requires a writable layer (-rwlayer, or the per-sandbox default)")
		}
		cfg.RW = true
	}
	cfg.RW = *f.RW || cfg.RW || (!set["rw"] && cfg.RWLayer != "")
	if cfg.RWLayer == "" && cfg.RW {
		cfg.RW = false
		warnings = append(warnings, "-rw: no writable layer found; running read-only. Create one with ./scripts/mkrwlayer.sh artifacts/rwlayer.ext4 512")
	}
	if cfg.RWLayer != "" {
		if w := rwlayerHealthWarning(cfg.RWLayer); w != "" {
			warnings = append(warnings, w)
		}
		if !explicitRWLayer {
			if err := checkRWLayerPairing(cfg.RWLayer, cfg.imageIdentity()); err != nil {
				return cfg, nil, err
			}
		}
	}

	cfg.Shares = *f.Shares
	if !cfg.RW && len(cfg.Shares) > 0 {
		return cfg, nil, fmt.Errorf("shares require a writable container root (remove -rw=false)")
	}
	cfg.Ports = *f.Publish
	cfg.Net = *f.Net
	cfg.GVProxy = *f.GVProxy
	if len(cfg.Ports) > 0 {
		if !cfg.Net {
			return cfg, nil, fmt.Errorf("port publishing requires networking (remove -net=false)")
		}
		if cfg.GVProxy != "" {
			return cfg, nil, fmt.Errorf("port publishing requires the embedded netstack (remove -gvproxy)")
		}
		seenPorts := map[string]bool{}
		for i, spec := range cfg.Ports {
			normalized, err := NormalizePortSpec(spec)
			if err != nil {
				return cfg, nil, fmt.Errorf("invalid -p %q: %v", spec, err)
			}
			m, _ := ParsePortSpec(normalized)
			if seenPorts[m.Key()] {
				return cfg, nil, fmt.Errorf("duplicate -p %q", spec)
			}
			seenPorts[m.Key()] = true
			cfg.Ports[i] = normalized
		}
	}
	if cfg.GVProxy != "" && !strings.ContainsRune(cfg.GVProxy, os.PathSeparator) && gutil.FileExists(cfg.GVProxy) {
		cfg.GVProxy = absPath(cfg.GVProxy)
	}
	// secrets: names only in the persisted config; the CLI resolves the
	// values via ResolveSecrets and hands them to the daemon over stdin
	// — never argv, never the environment, never a file
	if _, names, serr := f.ResolveSecrets(); serr != nil {
		return cfg, warnings, serr
	} else {
		cfg.SecretNames = names
	}

	cfg.ProcessIsolation = *f.ProcessIsolation
	switch cfg.ProcessIsolation {
	case "", "auto", "required", "off":
	default:
		return RunConfig{}, nil, fmt.Errorf("-process-isolation must be auto, required, or off, got %q", cfg.ProcessIsolation)
	}
	cfg.NetPol = *f.NetPol
	cfg.AllowLN = *f.AllowLN
	cfg.MemMB = *f.MemMB
	cfg.VCPUs = min(*f.VCPUs, 8)

	// absolute paths: the daemon runs with cwd=/
	cfg.Kernel = absPath(cfg.Kernel)
	cfg.Rootfs = absPath(cfg.Rootfs)
	cfg.Image = absPath(cfg.Image)
	if cfg.RWLayer != "" {
		cfg.RWLayer = absPath(cfg.RWLayer)
	}
	if cfg.NetPol != "" {
		cfg.NetPol = absPath(cfg.NetPol)
		if !gutil.FileExists(cfg.NetPol) {
			return cfg, nil, fmt.Errorf("network policy file %s does not exist", cfg.NetPol)
		}
	}

	for _, req := range []string{cfg.Kernel, cfg.Rootfs} {
		if !gutil.FileExists(req) {
			return cfg, nil, fmt.Errorf("missing %s", req)
		}
	}
	if cfg.LayerSet == nil && !gutil.FileExists(cfg.Image) {
		return cfg, nil, fmt.Errorf("missing %s", cfg.Image)
	}
	if cfg.RW && cfg.RWLayer != "" && !gutil.FileExists(cfg.RWLayer) {
		return cfg, nil, fmt.Errorf("rwlayer %s does not exist; create it with:\n  ./scripts/mkrwlayer.sh %s 512", cfg.RWLayer, cfg.RWLayer)
	}

	// validate share specs now, normalizing to absolute paths
	seen := map[string]bool{}
	for i, spec := range cfg.Shares {
		s, err := vmm.ParseShareSpec(spec, seen)
		if err != nil {
			return cfg, nil, fmt.Errorf("invalid -share %q: %v", spec, err)
		}
		seen[s.Tag] = true
		p, err := filepath.Abs(s.Path)
		if err == nil {
			cfg.Shares[i] = s.Tag + "=" + p
			if s.CtrPath != "" {
				cfg.Shares[i] += "@" + s.CtrPath // keep the explicit container path
			}
			if s.RO {
				cfg.Shares[i] += ",ro"
			}
			if s.UID != nil && s.GID != nil {
				// Round-trip the ownership mapping: cfg.Shares is persisted
				// and re-parsed, so dropping the suffix here would silently
				// turn -share ...,uid=N,gid=N into a no-op.
				cfg.Shares[i] += fmt.Sprintf(",uid=%d,gid=%d", *s.UID, *s.GID)
			}
		}
	}
	return cfg, warnings, nil
}

// ResolveSecrets parses -secret/-secret-file into the value map (CLI
// memory only — never serialized) plus the ordered unique names.
var osLookupEnv = os.LookupEnv

func (f *RunFlags) ResolveSecrets() (map[string]secret.Value, []string, error) {
	return secret.ResolveAll(f.Secrets.List(), f.SecretFiles.List(), osLookupEnv)
}

// ParsedShares validates cfg.Shares into virtio-fs share descriptors.
func (c RunConfig) ParsedShares() ([]vmm.Share, error) {
	var out []vmm.Share
	seen := map[string]bool{}
	for _, spec := range c.Shares {
		s, err := vmm.ParseShareSpec(spec, seen)
		if err != nil {
			return nil, err
		}
		seen[s.Tag] = true
		out = append(out, s)
	}
	return out, nil
}

// Network is a resolved network backend plus egress policy for one run.
type Network struct {
	Sock    string // external gvproxy endpoint ("" when embedded)
	Conn    net.Conn
	Stack   *vnet.Stack // nil for the gvproxy backend
	Policy  *netpol.Policy
	Traffic *netpol.TrafficRecorder
	// Backend is the control surface for live policy/port mutations:
	// the embedded stack in-process (monolithic) or the split network
	// worker over RPC. Nil for the gvproxy backend and -net=false.
	Backend NetworkBackend
	// Split reports that networking runs in a separate _net-worker
	// process: Conn is the supervisor end of the framed data channel.
	// Policy stays as the supervisor's authoritative copy for display
	// and rollback (Opts does NOT attach it to the device — enforcement
	// is the worker's), and Traffic is nil: the worker owns the
	// recorder writing traffic.json.
	Split  bool
	Worker *netWorker
	// Degraded lists isolation properties requested but not established
	// (auto mode only; required fails instead). Surfaced by the daemon.
	Degraded    []string
	close       func()
	backendOnce sync.Once
	trafficOnce sync.Once
}

// CloseBackend releases the netstack / gvproxy process / connection while
// leaving the traffic recorder alive until device shutdown completes.
func (n *Network) CloseBackend() {
	if n == nil {
		return
	}
	n.backendOnce.Do(func() {
		if n.close != nil {
			n.close()
		}
	})
}

// Close releases the backend and publishes the final traffic snapshot.
func (n *Network) Close() {
	if n == nil {
		return
	}
	n.CloseBackend()
	n.trafficOnce.Do(func() {
		if n.Traffic != nil {
			n.Traffic.Close()
		}
	})
}

// NetMarker is the "networking enabled" marker DefaultCmdline consumes.
func NetMarker(sock string, conn net.Conn) string {
	if sock != "" || conn != nil {
		return "enabled"
	}
	return ""
}

// StartNetwork builds the egress policy and brings up the configured
// backend. workdir holds the gvproxy socket/log when an external gvproxy
// is used. A nil *Network (with nil error) means -net=false.
func (c RunConfig) StartNetwork(workdir string) (*Network, error) {
	if (c.NetPol != "" || c.AllowLN) && c.GVProxy != "" {
		return nil, fmt.Errorf("-net-policy/-allow-local-net require the embedded netstack (drop -gvproxy)")
	}
	var policy *netpol.Policy
	if c.NetPol != "" {
		var err error
		policy, err = netpol.Load(c.NetPol)
		if err != nil {
			return nil, err
		}
	}
	if c.AllowLN {
		if policy == nil {
			policy = netpol.DefaultPolicy()
		}
		policy.AllowLocal = true
	}
	if policy == nil && c.Net {
		policy = netpol.DefaultPolicy() // internet yes, local net no
	}
	if !c.Net {
		return &Network{Policy: policy}, nil
	}

	n := &Network{Policy: policy}
	if c.GVProxy != "" {
		gv, sock, err := StartGVProxy(c.GVProxy, workdir)
		if err != nil {
			return nil, err
		}
		n.Sock = sock
		n.close = func() { _ = gv.Process.Kill(); _ = gv.Wait() }
		n.Traffic = netpol.NewTrafficRecorder(filepath.Join(workdir, netpol.TrafficFileName))
		return n, nil
	}
	if c.splitNetWorkerWanted() {
		worker, conn, err := startNetWorker(netWorkerConfig{
			GuestMAC:    net.HardwareAddr(guestNetMAC[:]).String(),
			Forwards:    portForwards(c.Ports),
			Policy:      mustMarshalPolicy(policy),
			TrafficPath: filepath.Join(workdir, netpol.TrafficFileName),
			Debug:       netWorkerTrafficDebug(),
			PcapPath:    gutil.EnvOr("GANTRY_NET_PCAP", "MINIVM_NET_PCAP"),
		})
		if err == nil {
			n.Conn = conn
			n.Backend = worker
			n.Split = true
			n.Worker = worker
			// The worker owns policy, traffic accounting (writing the
			// same traffic.json the TUI reads), and the stack; Close
			// shuts it down and reaps it.
			n.close = func() { _ = worker.Close() }
			return n, nil
		}
		if c.ProcessIsolation == "required" {
			return nil, fmt.Errorf("process isolation required but unavailable: %w", err)
		}
		n.Degraded = append(n.Degraded, "network-worker: "+err.Error())
		// auto: fall through to the monolithic embedded stack
	}

	stack, err := vnet.Start(guestNetMAC, portForwards(c.Ports))
	if err != nil {
		return nil, err
	}
	conn, err := stack.Dial()
	if err != nil {
		stack.Close()
		return nil, err
	}
	n.Conn = conn
	n.Stack = stack
	n.Backend = newLocalBackend(stack, policy)
	n.close = func() { _ = conn.Close(); stack.Close() }
	n.Traffic = netpol.NewTrafficRecorder(filepath.Join(workdir, netpol.TrafficFileName))
	return n, nil
}

// splitNetWorkerWanted reports whether StartNetwork should attempt the
// split network worker: networking on, embedded stack (gvproxy stays a
// monolithic compatibility path), and isolation not explicitly off.
func (c RunConfig) splitNetWorkerWanted() bool {
	return c.Net && c.GVProxy == "" && c.ProcessIsolation != "off"
}

// mustMarshalPolicy serializes the boot policy for the worker handshake.
// StartNetwork guarantees a non-nil, parsed policy on the split path, so
// a marshal failure is a bug, not user error.
func mustMarshalPolicy(policy *netpol.Policy) []byte {
	raw, err := netpol.Marshal(policy)
	if err != nil {
		panic(err)
	}
	return raw
}

// portForwards translates canonical publish specs into the netstack's
// static forward map ("udp:" key prefix for UDP, per gvisor-tap-vsock).
func portForwards(specs []string) map[string]string {
	if len(specs) == 0 {
		return nil
	}
	forwards := make(map[string]string, len(specs))
	for _, spec := range specs {
		m, err := ParsePortSpec(spec)
		if err != nil {
			continue // Resolve validated every spec
		}
		local := m.Local()
		if m.Proto == "udp" {
			local = "udp:" + local
		}
		forwards[local] = m.Remote()
	}
	return forwards
}

// imageIdentity is the stable identity used for rwlayer pairing: the
// OCI digest when the image came through the store, else the file path.
func (c RunConfig) imageIdentity() string {
	if c.LayerSet != nil {
		return "layerset:" + c.LayerSet.FSMeta
	}
	if c.ImageDigest != "" {
		return c.ImageDigest
	}
	return c.Image
}

// guestNetMAC is the fixed MAC the embedded netstack expects the guest to
// use (gvproxy-compatible pairing with the gateway MAC).
var guestNetMAC = [6]byte{0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee}

// Opts assembles vmm.Opts for the run. vsockFwd is the per-run socket
// directory. envExtra enables the GANTRY_EXTRA_CMDLINE debug knob (the
// daemon path; one-shot exec takes its cmdline exactly as resolved).
//
// All boot assets are opened HERE, up front: the returned Opts carries
// open descriptors, so the kernel/rootfs/layers a VM boots from are
// exactly the files that were resolved and validated — no path can be
// swapped between staging and boot, and a confined VMM worker needs no
// open-by-path rights at all. On success the Opts owns the files
// (Prepare consumes them); on error Opts closes what it opened.
func (c RunConfig) Opts(n *Network, hostShares []vmm.Share, vsockFwd string, envExtra bool) (vmm.Opts, error) {
	var o vmm.Opts
	fail := func(err error) (vmm.Opts, error) {
		for _, f := range append(append([]*os.File{o.Kernel, o.Initrd, o.Rootfs}, o.DisksRO...), o.Disks...) {
			if f != nil {
				_ = f.Close()
			}
		}
		return vmm.Opts{}, err
	}
	openRO := func(path, what string) (*os.File, error) {
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("%s %s: %w", what, path, err)
		}
		return f, nil
	}

	kernel, err := openRO(c.Kernel, "kernel")
	if err != nil {
		return fail(err)
	}
	o.Kernel = kernel
	arch, err := vmm.KernelArchFile(kernel)
	if err != nil {
		return fail(err)
	}
	if c.Rootfs != "" {
		if o.Rootfs, err = openRO(c.Rootfs, "rootfs"); err != nil {
			return fail(err)
		}
	}
	disksRO := []string{c.Image}
	if c.LayerSet != nil {
		disksRO = c.LayerSet.DisksRO()
	}
	for _, p := range disksRO {
		if p == "" {
			continue
		}
		f, err := openRO(p, "image layer")
		if err != nil {
			return fail(err)
		}
		o.DisksRO = append(o.DisksRO, f)
	}
	if c.RW && c.RWLayer != "" {
		f, err := os.OpenFile(c.RWLayer, os.O_RDWR, 0) // writable: /dev/vdc
		if err != nil {
			return fail(fmt.Errorf("rwlayer %s: %w", c.RWLayer, err))
		}
		o.Disks = append(o.Disks, f)
	}

	var sock string
	var conn net.Conn
	var policy *netpol.Policy
	var traffic *netpol.TrafficRecorder
	if n != nil && !n.Split {
		sock, conn, policy, traffic = n.Sock, n.Conn, n.Policy, n.Traffic
	} else if n != nil {
		// Split mode: the data channel crosses to the worker, which owns
		// enforcement and accounting — the device must not re-enforce or
		// double-count. The raw conn still flows (framing is the device's
		// job), policy and traffic stay nil.
		sock, conn = n.Sock, n.Conn
	}
	cmdline := vmm.DefaultCmdline(arch, c.Rootfs, "", 3, NetMarker(sock, conn), guestNetMAC, true)
	if envExtra {
		cmdline = gutil.InsertExtraCmdline(cmdline)
	}
	o.MemSize = uint64(c.MemMB) << 20
	o.Shares = hostShares
	o.NetEndpoint = sock
	o.NetConn = conn
	o.NetPolicy = policy
	o.NetTraffic = traffic
	o.NetMAC = guestNetMAC
	o.NetVFKIT = true
	o.VsockFwd = vsockFwd
	o.VCPUs = c.VCPUs
	o.GuestCID = 3
	o.VsockListen = []uint32{1026}
	o.Cmdline = cmdline
	return o, nil
}

// isErofsFile reports whether p is an existing plain file with the
// .erofs suffix — the one -image form that needs no resolution.
func isErofsFile(p string) bool {
	if !strings.HasSuffix(p, ".erofs") {
		return false
	}
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}
