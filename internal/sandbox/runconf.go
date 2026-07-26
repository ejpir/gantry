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
	"gantry/internal/gutil"
	"gantry/internal/netpol"
	"gantry/internal/vmm"
	"gantry/internal/vnet"
	"net"
	"os"
	"path/filepath"
	"strings"
)

// RunConfig is the fully-resolved description of one gantry VM run.
// sandbox.json is this struct.
type RunConfig struct {
	Kernel  string   `json:"kernel"`
	Rootfs  string   `json:"rootfs"`
	Runtime string   `json:"runtime,omitempty"`
	Image   string   `json:"image"`
	RWLayer string   `json:"rwlayer,omitempty"`
	RW      bool     `json:"rw"`
	Shares  []string `json:"shares,omitempty"` // raw TAG=PATH[,ro] specs, absolute
	Net     bool     `json:"net"`
	GVProxy string   `json:"gvproxy,omitempty"`
	NetPol  string   `json:"net_policy,omitempty"`
	AllowLN bool     `json:"allow_local_net,omitempty"`
	MemMB   uint     `json:"memMB"`
	VCPUs   int      `json:"vcpus,omitempty"`
}

// RunFlags holds the CLI flag pointers shared by `gantry exec` and
// `gantry start`. Register them on the FlagSet, parse, then Resolve.
type RunFlags struct {
	Kernel, Rootfs, Runtime, Image, RWLayer *string
	RW                                      *bool
	Shares                                  *gutil.StrList
	Net                                     *bool
	GVProxy, NetPol                         *string
	AllowLN                                 *bool
	MemMB                                   *uint
	VCPUs                                   *int
}

// RegisterRunFlags adds the shared run flags to fs.
func RegisterRunFlags(fs *flag.FlagSet) *RunFlags {
	f := &RunFlags{
		Kernel:  fs.String("kernel", vmm.DefaultKernelImage(), "Linux kernel image (arm64 Image or x86-64 vmlinux ELF)"),
		Rootfs:  fs.String("rootfs", vmm.DefaultRootfs(), "VM rootfs (nerdbox EROFS with vminitd)"),
		Image:   fs.String("image", "", "container rootfs disk, /dev/vdb (default: debian-bookworm.erofs if present, else shell-rootfs.erofs)"),
		RWLayer: fs.String("rwlayer", "", "ext4 writable layer, /dev/vdc (default: rwlayer.ext4 if present)"),
		RW:      fs.Bool("rw", false, "writable overlay container root (default: on when a rwlayer is available)"),
		Net:     fs.Bool("net", true, "attach virtio-net via the embedded netstack"),
		GVProxy: fs.String("gvproxy", "", "use this external gvproxy binary instead of the embedded netstack"),
		NetPol:  fs.String("net-policy", "", "JSON egress policy file (rules + domain allowlist)"),
		AllowLN: fs.Bool("allow-local-net", false, "let the sandbox reach LAN/link-local/host (default: internet only)"),
		MemMB:   fs.Uint("mem", 512, "guest RAM in MiB"),
		VCPUs:   fs.Int("cpus", 1, "guest vCPU count (max 8)"),
		Shares:  &gutil.StrList{},
	}
	f.Runtime = fs.String("runtime", func() string {
		if v := gutil.EnvOr("GANTRY_RUNTIME", "MINIVM_RUNTIME"); v != "" {
			return v
		}
		return "crun"
	}(), "container runtime in the guest: crun | runsc (gVisor)")
	fs.Var(f.Shares, "share", "host directory exported through virtio-fs as TAG=PATH[,ro] (repeatable)")
	return f
}

// Resolve turns parsed flags into an absolute, fully-defaulted RunConfig.
// warnings are non-fatal degradations the caller should surface to the
// user (e.g. -rw silently dropped because no rwlayer exists).
func (f *RunFlags) Resolve(fs *flag.FlagSet) (cfg RunConfig, warnings []string, err error) {
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
		if !gutil.FileExists(cfg.Rootfs) {
			return cfg, nil, fmt.Errorf("%s not found - build it with ./mkrootfs-gvisor.sh %s", cfg.Rootfs, vmm.DefaultRootfs())
		}
		if !set["kernel"] {
			cfg.Kernel = vmm.GvisorKernel(cfg.Kernel)
		}
		if cfg.Kernel != "" && !gutil.FileExists(cfg.Kernel) {
			return cfg, nil, fmt.Errorf("%s not found - gVisor needs the 4K-page kernel, build it with ./mkkernel-4k.sh", cfg.Kernel)
		}
	default:
		return cfg, nil, fmt.Errorf("-runtime must be crun or runsc, got %q", cfg.Runtime)
	}

	cfg.Image = *f.Image
	if cfg.Image == "" {
		if gutil.FileExists("debian-bookworm.erofs") {
			cfg.Image = "debian-bookworm.erofs"
		} else {
			cfg.Image = "shell-rootfs.erofs"
		}
	}
	cfg.RWLayer = *f.RWLayer
	if cfg.RWLayer == "" && gutil.FileExists("rwlayer.ext4") {
		cfg.RWLayer = "rwlayer.ext4"
	}
	// -rw rules: default on when a writable layer exists, forced off when
	// none does — never hand the guest RW=true for a disk we didn't attach.
	cfg.RW = *f.RW || (!set["rw"] && cfg.RWLayer != "")
	if cfg.RWLayer == "" && cfg.RW {
		cfg.RW = false
		warnings = append(warnings, "-rw: no writable layer (rwlayer.ext4) found; running read-only. Create one with ./mkrwlayer.sh rwlayer.ext4 512")
	}

	cfg.Shares = *f.Shares
	cfg.Net = *f.Net
	cfg.GVProxy = *f.GVProxy
	if cfg.GVProxy != "" && !strings.ContainsRune(cfg.GVProxy, os.PathSeparator) && gutil.FileExists(cfg.GVProxy) {
		cfg.GVProxy = absPath(cfg.GVProxy)
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

	for _, req := range []string{cfg.Kernel, cfg.Rootfs, cfg.Image} {
		if !gutil.FileExists(req) {
			return cfg, nil, fmt.Errorf("missing %s", req)
		}
	}
	if cfg.RW && cfg.RWLayer != "" && !gutil.FileExists(cfg.RWLayer) {
		return cfg, nil, fmt.Errorf("rwlayer %s does not exist; create it with:\n  ./mkrwlayer.sh %s 512", cfg.RWLayer, cfg.RWLayer)
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
			if s.RO {
				cfg.Shares[i] += ",ro"
			}
		}
	}
	return cfg, warnings, nil
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
	Sock   string // external gvproxy endpoint ("" when embedded)
	Conn   net.Conn
	Policy *netpol.Policy
	close  func()
}

// Close releases the backend (netstack / gvproxy process / conn).
func (n *Network) Close() {
	if n != nil && n.close != nil {
		n.close()
	}
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
		n.close = func() { gv.Process.Kill(); gv.Wait() }
		return n, nil
	}
	stack, err := vnet.Start(guestNetMAC)
	if err != nil {
		return nil, err
	}
	conn, err := stack.Dial()
	if err != nil {
		stack.Close()
		return nil, err
	}
	n.Conn = conn
	n.close = func() { conn.Close(); stack.Close() }
	return n, nil
}

// guestNetMAC is the fixed MAC the embedded netstack expects the guest to
// use (gvproxy-compatible pairing with the gateway MAC).
var guestNetMAC = [6]byte{0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee}

// Opts assembles vmm.Opts for the run. vsockFwd is the per-run socket
// directory. envExtra enables the GANTRY_EXTRA_CMDLINE debug knob (the
// daemon path; one-shot exec takes its cmdline exactly as resolved).
func (c RunConfig) Opts(n *Network, hostShares []vmm.Share, vsockFwd string, envExtra bool) (vmm.Opts, error) {
	disks := []string{c.Image}
	if c.RW && c.RWLayer != "" {
		disks = append(disks, c.RWLayer)
	}
	arch, err := vmm.KernelArch(c.Kernel)
	if err != nil {
		return vmm.Opts{}, err
	}
	var sock string
	var conn net.Conn
	var policy *netpol.Policy
	if n != nil {
		sock, conn, policy = n.Sock, n.Conn, n.Policy
	}
	cmdline := vmm.DefaultCmdline(arch, c.Rootfs, "", 3, NetMarker(sock, conn), guestNetMAC, true)
	if envExtra {
		cmdline = gutil.InsertExtraCmdline(cmdline)
	}
	return vmm.Opts{
		MemSize:     uint64(c.MemMB) << 20,
		KernelPath:  c.Kernel,
		RootfsPath:  c.Rootfs,
		Disks:       disks,
		Shares:      hostShares,
		NetEndpoint: sock,
		NetConn:     conn,
		NetPolicy:   policy,
		NetMAC:      guestNetMAC,
		NetVFKIT:    true,
		VsockFwd:    vsockFwd,
		VCPUs:       c.VCPUs,
		GuestCID:    3,
		VsockListen: []uint32{1026},
		Cmdline:     cmdline,
	}, nil
}
