package sandbox

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ejpir/gantry/internal/client"
	"github.com/ejpir/gantry/internal/guestasset"
	"github.com/ejpir/gantry/internal/gutil"
	"github.com/ejpir/gantry/internal/image"
	"github.com/ejpir/gantry/internal/mcpspec"
	"github.com/ejpir/gantry/internal/netpol"
	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/layout"
	"github.com/ejpir/gantry/internal/sandbox/rwlayer"
	"github.com/ejpir/gantry/internal/secret"
	"github.com/ejpir/gantry/internal/shares"
	"github.com/ejpir/gantry/internal/vmm"
)

type explicitRunFlags struct {
	kernel   bool
	rootfs   bool
	rw       bool
	mem      bool
	vcpus    bool
	diskSize bool
}

func collectExplicitRunFlags(fs *flag.FlagSet) (set explicitRunFlags) {
	fs.Visit(func(flag *flag.Flag) {
		switch flag.Name {
		case "kernel":
			set.kernel = true
		case "rootfs":
			set.rootfs = true
		case "rw":
			set.rw = true
		case "mem":
			set.mem = true
		case "cpus":
			set.vcpus = true
		case "disk-size":
			set.diskSize = true
		}
	})
	return set
}

type runResolver struct {
	flags      *config.RunFlags
	explicit   explicitRunFlags
	cfg        config.RunConfig
	warnings   []string
	progress   func(string, ...any)
	cachedOnly bool
}

// Resolve turns parsed flags into an absolute, fully-defaulted RunConfig.
// Warnings are non-fatal degradations surfaced by the caller. Progress may be
// nil; when present, slow registry and asset operations report synchronously.
func Resolve(f *config.RunFlags, fs *flag.FlagSet, progress func(string, ...any)) (config.RunConfig, []string, error) {
	return resolveFlags(f, fs, progress, nil)
}

// resolve is Resolve with optional low-overhead launcher milestones. Keeping
// the hook here attributes work before the daemon exists (asset checks, image
// freshness, and writable-layer setup) without changing normal CLI output.
func resolveFlags(f *config.RunFlags, fs *flag.FlagSet, progress func(string, ...any), milestone func(string)) (config.RunConfig, []string, error) {
	return resolveFlagsWithPolicy(f, fs, progress, milestone, false)
}

func resolveFlagsWithPolicy(f *config.RunFlags, fs *flag.FlagSet, progress func(string, ...any), milestone func(string), cachedOnly bool) (config.RunConfig, []string, error) {
	r := runResolver{
		flags:      f,
		explicit:   collectExplicitRunFlags(fs),
		progress:   progress,
		cachedOnly: cachedOnly,
	}
	mark := func(phase string) {
		if milestone != nil {
			milestone(phase)
		}
	}
	if err := r.initialize(); err != nil {
		return r.cfg, r.warnings, err
	}
	// Session options are structural and side-effect free. Resolve them before
	// secrets so -mcp-remote (which implies MCP) also stages the guest helper.
	if err := r.resolveSessionOptions(); err != nil {
		return r.cfg, r.warnings, err
	}
	// Secrets validate before any on-disk artifacts are created (the
	// per-sandbox writable layer in particular): a bad -secret spec must
	// fail the start without leaving a fresh 512 MiB rwlayer behind.
	if err := r.resolveSecrets(); err != nil {
		return r.cfg, r.warnings, err
	}
	if err := r.resolveRuntime(); err != nil {
		return r.cfg, r.warnings, err
	}
	mark("launcher runtime resolved")
	if err := r.resolveBootAssets(); err != nil {
		return r.cfg, r.warnings, err
	}
	mark("launcher boot assets resolved")
	if err := r.resolveImage(); err != nil {
		return r.cfg, r.warnings, err
	}
	mark("launcher image resolved")
	if err := r.resolveWritableLayer(); err != nil {
		return r.cfg, r.warnings, err
	}
	mark("launcher writable layer resolved")
	if err := r.resolveNetworking(); err != nil {
		return r.cfg, r.warnings, err
	}
	if err := r.normalizeAndValidatePaths(); err != nil {
		return r.cfg, r.warnings, err
	}
	mark("launcher configuration resolved")
	return r.cfg, r.warnings, nil
}

func (r *runResolver) initialize() error {
	if *r.flags.DevContainers {
		if !r.explicit.mem {
			*r.flags.MemMB = min(config.DefaultDevContainersMemoryMiB, uint(config.MaxSandboxMemMB))
		}
		if !r.explicit.vcpus {
			*r.flags.VCPUs = min(config.DefaultDevContainersVCPUs, config.MaxSandboxVCPUs())
		}
		if !r.explicit.diskSize {
			*r.flags.RWLayerSizeMiB = config.DefaultDevContainersDiskSizeMiB
		}
	}
	if err := config.ValidateSandboxResources(*r.flags.MemMB, *r.flags.VCPUs); err != nil {
		return err
	}
	if err := config.ValidateRWLayerSize(*r.flags.RWLayerSizeMiB); err != nil {
		return err
	}
	r.cfg.MemMB = *r.flags.MemMB
	r.cfg.VCPUs = *r.flags.VCPUs
	r.cfg.RWLayerSizeMiB = *r.flags.RWLayerSizeMiB
	return nil
}

func (r *runResolver) resolveRuntime() error {
	r.cfg.Runtime = *r.flags.Runtime
	r.cfg.Kernel = *r.flags.Kernel
	if r.explicit.kernel {
		r.cfg.KernelPolicy = config.KernelPolicyPinned
	} else {
		r.cfg.KernelPolicy = config.KernelPolicyRelease
	}
	r.cfg.Rootfs = *r.flags.Rootfs
	switch r.cfg.Runtime {
	case "crun":
		return nil
	case "runsc":
		if !r.explicit.rootfs {
			r.cfg.Rootfs = guestasset.GVisorRootfs(r.cfg.Rootfs)
		}
		if !r.explicit.kernel {
			r.cfg.Kernel = guestasset.GVisorKernel(r.cfg.Kernel)
		}
		return nil
	default:
		return fmt.Errorf("-runtime must be crun or runsc, got %q", r.cfg.Runtime)
	}
}

func (r *runResolver) resolveBootAssets() error {
	if r.cfg.Kernel != "" && !gutil.FileExists(r.cfg.Kernel) {
		if r.explicit.kernel {
			return fmt.Errorf("kernel %s not found", r.cfg.Kernel)
		}
		kernel, err := guestasset.EnsureKernel(r.cfg.Kernel, r.report)
		if err != nil {
			hint := "build it with ./scripts/mkkernel.sh"
			if r.cfg.Runtime == "runsc" {
				hint = "gVisor needs the 4K-page kernel: PAGES=4k ./scripts/mkkernel.sh"
			}
			return fmt.Errorf("%w (%s)", err, hint)
		}
		r.cfg.Kernel = kernel
	}

	if r.cfg.Rootfs == "" || gutil.FileExists(r.cfg.Rootfs) {
		return nil
	}
	if r.explicit.rootfs {
		return fmt.Errorf("rootfs %s not found", r.cfg.Rootfs)
	}
	rootfs, err := guestasset.EnsureRootfs(r.cfg.Rootfs, r.report)
	if err != nil {
		hint := "copy nerdbox-rootfs-<arch>.erofs from a nerdbox release into artifacts/, or build from source"
		if r.cfg.Runtime == "runsc" {
			hint = "or build it locally with ./scripts/mkrootfs-gvisor.sh " + guestasset.DefaultRootfs()
		}
		return fmt.Errorf("%w (%s)", err, hint)
	}
	r.cfg.Rootfs = rootfs
	return nil
}

func defaultDevContainersImageConfig() *image.Config {
	return &image.Config{
		Env: []string{
			"HOME=/home/gantry",
			"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		},
		Cmd: []string{"/bin/bash"}, User: "gantry", UID: 1000, GID: 1000,
		WorkingDir: "/home/gantry",
	}
}

func (r *runResolver) resolveImage() error {
	r.cfg.Image = *r.flags.Image
	if r.cfg.Image == "" {
		r.cfg.Image = guestasset.DefaultImage()
		if r.cfg.DevContainers && *r.flags.LayerSet == "" {
			r.cfg.Image = guestasset.DefaultDevContainersImage()
			r.cfg.ImageCfg = defaultDevContainersImageConfig()
		}
		if !gutil.FileExists(r.cfg.Image) {
			imagePath, err := guestasset.EnsureImage(r.cfg.Image, r.report)
			if err != nil {
				// An unstaged development default must not fall into registry
				// resolution: ParseRef would normalize a bare name like
				// shell-rootfs.erofs into a docker.io library/ pull. Tagged
				// releases reach this path only when their verified default
				// image download failed.
				return fmt.Errorf("no default image available: %w\npass -image <ref-or-file> explicitly (see 'gantry image ls' and 'gantry image pull')", err)
			}
			r.cfg.Image = imagePath
		}
	}
	if *r.flags.LayerSet != "" {
		layers, err := client.LoadLayerSet(*r.flags.LayerSet)
		if err != nil {
			return err
		}
		if err := layers.Validate(); err != nil {
			return err
		}
		r.cfg.LayerSet = layers
	}
	if r.cfg.LayerSet != nil || config.IsErofsFile(r.cfg.Image) {
		return nil
	}

	arch, err := kernelArch(r.cfg.Kernel)
	if err != nil {
		return err
	}
	var resolved *image.Resolved
	if r.cachedOnly {
		resolved, err = image.ResolveCachedOnly(r.cfg.Image, arch, nil, r.report)
	} else {
		resolved, err = image.ResolvePreferCached(r.cfg.Image, arch, nil, r.report)
	}
	if err != nil {
		return err
	}
	if resolved.Config != nil {
		r.cfg.ImageRef = resolved.Ref
		r.cfg.ImageDigest = resolved.Digest
		r.cfg.ImageCfg = resolved.Config
	}
	r.cfg.Image = resolved.Path
	return nil
}

func kernelArch(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open kernel %s: %w", path, err)
	}
	defer func() { _ = file.Close() }()
	return vmm.KernelArchFile(file)
}

func (r *runResolver) resolveWritableLayer() error {
	if r.cfg.LayerSet != nil && r.explicit.rw && !*r.flags.RW {
		return fmt.Errorf("a layerset is a writable overlay pair (remove -rw=false)")
	}

	r.cfg.RWLayer = *r.flags.RWLayer
	explicitLayer := r.cfg.RWLayer != ""
	switch {
	case r.cfg.RWLayer != "":
	case r.explicit.rw && !*r.flags.RW:
		// An explicitly read-only VM cannot attach a writable layer. In
		// particular, do not format the implicit per-sandbox ext4.
	case r.flags.Name != "":
		path, warnings, err := rwlayer.Default(r.flags.Name, r.cfg.ImageIdentity(), r.cfg.RWLayerSizeMiB, r.report)
		if err != nil {
			return err
		}
		r.cfg.RWLayer = path
		r.warnings = append(r.warnings, warnings...)
	case gutil.FileExists(guestasset.Path("rwlayer.ext4")):
		r.cfg.RWLayer = guestasset.Path("rwlayer.ext4")
		explicitLayer = true
	}

	if r.cfg.LayerSet != nil {
		if r.cfg.RWLayer == "" {
			return fmt.Errorf("a layerset requires a writable layer (-rwlayer, or the per-sandbox default)")
		}
		r.cfg.RW = true
	}
	r.cfg.RW = *r.flags.RW || r.cfg.RW || (!r.explicit.rw && r.cfg.RWLayer != "")
	if r.cfg.RWLayer == "" && r.cfg.RW {
		r.cfg.RW = false
		r.warnings = append(r.warnings, "-rw: no writable layer found; running read-only. Create one with ./scripts/mkrwlayer.sh artifacts/rwlayer.ext4 512")
	}
	if r.cfg.RWLayer == "" {
		return nil
	}
	if warning := rwlayer.HealthWarning(r.cfg.RWLayer); warning != "" {
		r.warnings = append(r.warnings, warning)
	}
	if explicitLayer {
		return nil
	}
	return rwlayer.CheckPairing(r.cfg.RWLayer, r.cfg.ImageIdentity())
}

func (r *runResolver) resolveNetworking() error {
	r.cfg.Shares = append([]string(nil), (*r.flags.Shares)...)
	if !r.cfg.RW && len(r.cfg.Shares) != 0 {
		return fmt.Errorf("shares require a writable container root (remove -rw=false)")
	}
	r.cfg.Ports = append([]string(nil), (*r.flags.Publish)...)
	r.cfg.Net = *r.flags.Net
	r.cfg.GVProxy = *r.flags.GVProxy
	proxy, err := config.ParseForwardProxy(*r.flags.ProxyURL)
	if err != nil {
		return err
	}
	r.cfg.ProxyURL = proxy.URL
	r.cfg.NoProxy = *r.flags.NoProxy
	r.cfg.ProxyEnforce = *r.flags.ProxyEnforce
	if err := config.ValidateProxyConfig(r.cfg); err != nil {
		return err
	}
	if len(r.cfg.Ports) != 0 {
		if !r.cfg.Net {
			return fmt.Errorf("port publishing requires networking (remove -net=false)")
		}
		if r.cfg.GVProxy != "" {
			return fmt.Errorf("port publishing requires the embedded netstack (remove -gvproxy)")
		}
	}

	seen := make(map[string]struct{}, len(r.cfg.Ports))
	for index, spec := range r.cfg.Ports {
		normalized, err := config.NormalizePortSpec(spec)
		if err != nil {
			return fmt.Errorf("invalid -p %q: %w", spec, err)
		}
		mapping, err := config.ParsePortSpec(normalized)
		if err != nil {
			return fmt.Errorf("normalize -p %q: %w", spec, err)
		}
		if _, duplicate := seen[mapping.Key()]; duplicate {
			return fmt.Errorf("duplicate -p %q", spec)
		}
		seen[mapping.Key()] = struct{}{}
		r.cfg.Ports[index] = normalized
	}
	if r.cfg.GVProxy != "" && !strings.ContainsRune(r.cfg.GVProxy, os.PathSeparator) && gutil.FileExists(r.cfg.GVProxy) {
		r.cfg.GVProxy = layout.AbsPath(r.cfg.GVProxy)
	}
	return nil
}

func (r *runResolver) resolveSecrets() error {
	_, sources, names, err := r.flags.ResolveSecretSources()
	if err != nil {
		return err
	}
	r.cfg.SecretNames = names
	r.cfg.SecretSources = sources
	// Host-bound secrets (NAME@host), OAuth custody, MCP, and SSH all need
	// the multicall helper inside the guest (credential, gateway, verified
	// user, SFTP, and loopback relay modes).
	// Stage the asset here — during CLI resolution, with progress — so a
	// first-run download never lands on the VM boot path. Failure to stage
	// is not fatal: the daemon warns loudly at delivery time instead.
	if hasBoundSecrets(names) || *r.flags.OAuthCustody || *r.flags.MCP || *r.flags.SSH {
		path, err := guestasset.EnsureGuestTools(guestasset.DefaultGuestTools(), r.report)
		if err != nil {
			// Not fatal: the daemon warns loudly at delivery time instead.
			r.report("guest tools for bound secrets not staged: %v", err)
		} else {
			// The daemon runs with cwd "/": persist the resolved absolute
			// path so its asset lookup cannot diverge from the CLI's.
			if err := makeAbsolute("guest-tools", &path); err != nil {
				return err
			}
			r.cfg.GuestTools = path
		}
	}
	r.warnBoundSecretsVsPolicy(names, sources)
	return nil
}

// warnBoundSecretsVsPolicy surfaces, at sandbox creation time, bound
// secrets whose domains the egress policy's domain allowlist does not
// cover: the broker would hold the value but the credhelper refuses every
// guest request for it (a brokered token never outruns the firewall), an
// expensive no-op the owner should hear about before boot. With no
// allowlist the policy does not filter by name at all, so there is
// nothing to warn about; a policy that fails to parse is reported by
// network bring-up, not here.
func (r *runResolver) warnBoundSecretsVsPolicy(names []string, sources []secret.NamedSource) {
	if r.flags.NetPol == nil || *r.flags.NetPol == "" {
		return
	}
	policy, err := netpol.Load(*r.flags.NetPol)
	if err != nil {
		return
	}
	warn := func(name, binding string) {
		if binding != "" && !policy.DomainAllowed(binding) {
			r.report("WARNING: bound secret %s (@%s) is not covered by the -net-policy domain allowlist; the credential broker will refuse guest requests for it", name, binding)
		}
	}
	for _, name := range names {
		_, binding, err := secret.SplitBinding(name)
		if err != nil {
			continue // malformed specs fail earlier, at secret parse
		}
		warn(name, binding)
	}
	for _, s := range sources {
		warn(s.Name, s.Source.Binding)
	}
}

func (r *runResolver) resolveSessionOptions() error {
	r.cfg.ProcessIsolation = *r.flags.ProcessIsolation
	if err := config.ValidateProcessIsolation(r.cfg.ProcessIsolation); err != nil {
		return fmt.Errorf("-process-isolation must be auto, required, or off, got %q", r.cfg.ProcessIsolation)
	}
	r.cfg.NetPol = *r.flags.NetPol
	r.cfg.AllowLN = *r.flags.AllowLN
	enabled := *r.flags.OAuthBridge
	r.cfg.OAuthBridge = &enabled
	custody := *r.flags.OAuthCustody
	r.cfg.OAuthCustody = &custody
	if custody && !enabled {
		return fmt.Errorf("-oauth-custody requires -oauth-bridge=true")
	}
	r.cfg.MCP = *r.flags.MCP
	r.cfg.SSH = *r.flags.SSH
	r.cfg.DevContainers = *r.flags.DevContainers
	if r.cfg.DevContainers && !r.cfg.SSH {
		return fmt.Errorf("-devcontainers requires -ssh")
	}
	r.cfg.MCPFSRoot = *r.flags.MCPFSRoot
	r.cfg.MCPFSUser = *r.flags.MCPFSUser
	r.cfg.MCPRemotes = append([]string{}, (*r.flags.MCPRemotes)...)
	if len(r.cfg.MCPRemotes) > mcpspec.MaxRemotes {
		return fmt.Errorf("too many -mcp-remote values (max %d)", mcpspec.MaxRemotes)
	}
	if len(r.cfg.MCPRemotes) > 0 {
		r.cfg.MCP = true // remotes imply the gateway
	}
	// Structural validation happens here (before any boot work) so a bad
	// spec refuses the start loudly and immediately; the daemon re-parses
	// for secret/custody resolution against its live stores.
	seenMCPNames := make(map[string]bool, len(r.cfg.MCPRemotes))
	for _, spec := range r.cfg.MCPRemotes {
		remote, err := parseMCPRemote(spec)
		if err != nil {
			return fmt.Errorf("-mcp-remote %q: %w", spec, err)
		}
		if seenMCPNames[remote.Name] {
			return fmt.Errorf("-mcp-remote %q: duplicate server name %q", spec, remote.Name)
		}
		seenMCPNames[remote.Name] = true
	}
	if r.cfg.MCP {
		root, user, err := config.NormalizeMCPFilesystem(r.cfg.MCPFSRoot, r.cfg.MCPFSUser)
		if err != nil {
			return err
		}
		r.cfg.MCPFSRoot, r.cfg.MCPFSUser = root, user
	}
	return nil
}

func (r *runResolver) normalizeAndValidatePaths() error {
	if err := config.ValidateDevContainers(r.cfg); err != nil {
		return fmt.Errorf("-devcontainers: %w", err)
	}
	if err := makeAbsolute("kernel", &r.cfg.Kernel); err != nil {
		return err
	}
	if err := makeAbsolute("rootfs", &r.cfg.Rootfs); err != nil {
		return err
	}
	if err := makeAbsolute("image", &r.cfg.Image); err != nil {
		return err
	}
	if err := makeAbsolute("rwlayer", &r.cfg.RWLayer); err != nil {
		return err
	}
	if err := makeAbsolute("netpol", &r.cfg.NetPol); err != nil {
		return err
	}
	if r.cfg.NetPol != "" && !gutil.FileExists(r.cfg.NetPol) {
		return fmt.Errorf("network policy file %s does not exist", r.cfg.NetPol)
	}
	for _, required := range []string{r.cfg.Kernel, r.cfg.Rootfs} {
		if !gutil.FileExists(required) {
			return fmt.Errorf("missing %s", required)
		}
	}
	if r.cfg.LayerSet == nil && !gutil.FileExists(r.cfg.Image) {
		return fmt.Errorf("missing %s", r.cfg.Image)
	}
	if r.cfg.RW && r.cfg.RWLayer != "" && !gutil.FileExists(r.cfg.RWLayer) {
		return fmt.Errorf("rwlayer %s does not exist; create it with:\n  ./scripts/mkrwlayer.sh %s 512", r.cfg.RWLayer, r.cfg.RWLayer)
	}

	parsed, err := shares.ParseSpecs(r.cfg.Shares)
	if err != nil {
		return fmt.Errorf("invalid -share: %w", err)
	}
	for index, share := range parsed {
		absolute, err := filepath.Abs(share.Path)
		if err != nil {
			return fmt.Errorf("resolve share path %q: %w", share.Path, err)
		}
		share.Path = absolute
		r.cfg.Shares[index] = share.String()
	}
	return nil
}

func makeAbsolute(name string, target *string) error {
	if *target == "" {
		return nil
	}
	absolute, err := filepath.Abs(*target)
	if err != nil {
		return fmt.Errorf("resolve %s path %q: %w", name, *target, err)
	}
	*target = absolute
	return nil
}

func (r *runResolver) report(format string, args ...any) {
	if r.progress != nil {
		r.progress(format, args...)
	}
}
