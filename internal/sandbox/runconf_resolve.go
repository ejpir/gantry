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
	"github.com/ejpir/gantry/internal/shares"
	"github.com/ejpir/gantry/internal/vmm"
)

type explicitRunFlags struct {
	kernel bool
	rootfs bool
	rw     bool
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
		}
	})
	return set
}

type runResolver struct {
	flags    *RunFlags
	explicit explicitRunFlags
	cfg      RunConfig
	warnings []string
	progress func(string, ...any)
}

// Resolve turns parsed flags into an absolute, fully-defaulted RunConfig.
// Warnings are non-fatal degradations surfaced by the caller. Progress may be
// nil; when present, slow registry and asset operations report synchronously.
func (f *RunFlags) Resolve(fs *flag.FlagSet, progress func(string, ...any)) (RunConfig, []string, error) {
	r := runResolver{
		flags:    f,
		explicit: collectExplicitRunFlags(fs),
		progress: progress,
	}
	if err := r.initialize(); err != nil {
		return r.cfg, r.warnings, err
	}
	if err := r.resolveRuntime(); err != nil {
		return r.cfg, r.warnings, err
	}
	if err := r.resolveBootAssets(); err != nil {
		return r.cfg, r.warnings, err
	}
	if err := r.resolveImage(); err != nil {
		return r.cfg, r.warnings, err
	}
	if err := r.resolveWritableLayer(); err != nil {
		return r.cfg, r.warnings, err
	}
	if err := r.resolveNetworking(); err != nil {
		return r.cfg, r.warnings, err
	}
	if err := r.resolveSessionOptions(); err != nil {
		return r.cfg, r.warnings, err
	}
	if err := r.normalizeAndValidatePaths(); err != nil {
		return r.cfg, r.warnings, err
	}
	return r.cfg, r.warnings, nil
}

func (r *runResolver) initialize() error {
	if err := validateSandboxResources(*r.flags.MemMB, *r.flags.VCPUs); err != nil {
		return err
	}
	r.cfg.MemMB = *r.flags.MemMB
	r.cfg.VCPUs = *r.flags.VCPUs
	return nil
}

func (r *runResolver) resolveRuntime() error {
	r.cfg.Runtime = *r.flags.Runtime
	r.cfg.Kernel = *r.flags.Kernel
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

func (r *runResolver) resolveImage() error {
	r.cfg.Image = *r.flags.Image
	if r.cfg.Image == "" {
		r.cfg.Image = guestasset.DefaultImage()
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
	if r.cfg.LayerSet != nil || isErofsFile(r.cfg.Image) {
		return nil
	}

	arch, err := kernelArch(r.cfg.Kernel)
	if err != nil {
		return err
	}
	resolved, err := image.Resolve(r.cfg.Image, arch, nil, r.report)
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
	r.cfg.RWLayer = *r.flags.RWLayer
	explicitLayer := r.cfg.RWLayer != ""
	switch {
	case r.cfg.RWLayer != "":
	case r.flags.Name != "":
		path, warnings, err := defaultRWLayer(r.flags.Name, r.cfg.imageIdentity())
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
		if r.explicit.rw && !*r.flags.RW {
			return fmt.Errorf("a layerset is a writable overlay pair (remove -rw=false)")
		}
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
	if warning := rwlayerHealthWarning(r.cfg.RWLayer); warning != "" {
		r.warnings = append(r.warnings, warning)
	}
	if explicitLayer {
		return nil
	}
	return checkRWLayerPairing(r.cfg.RWLayer, r.cfg.imageIdentity())
}

func (r *runResolver) resolveNetworking() error {
	r.cfg.Shares = append([]string(nil), (*r.flags.Shares)...)
	if !r.cfg.RW && len(r.cfg.Shares) != 0 {
		return fmt.Errorf("shares require a writable container root (remove -rw=false)")
	}
	r.cfg.Ports = append([]string(nil), (*r.flags.Publish)...)
	r.cfg.Net = *r.flags.Net
	r.cfg.GVProxy = *r.flags.GVProxy
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
		normalized, err := NormalizePortSpec(spec)
		if err != nil {
			return fmt.Errorf("invalid -p %q: %w", spec, err)
		}
		mapping, err := ParsePortSpec(normalized)
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
		r.cfg.GVProxy = absPath(r.cfg.GVProxy)
	}
	return nil
}

func (r *runResolver) resolveSessionOptions() error {
	_, names, err := r.flags.ResolveSecrets()
	if err != nil {
		return err
	}
	r.cfg.SecretNames = names
	r.cfg.ProcessIsolation = *r.flags.ProcessIsolation
	switch r.cfg.ProcessIsolation {
	case "", "auto", "required", "off":
	default:
		return fmt.Errorf("-process-isolation must be auto, required, or off, got %q", r.cfg.ProcessIsolation)
	}
	r.cfg.NetPol = *r.flags.NetPol
	r.cfg.AllowLN = *r.flags.AllowLN
	enabled := *r.flags.OAuthBridge
	r.cfg.OAuthBridge = &enabled
	return nil
}

func (r *runResolver) normalizeAndValidatePaths() error {
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
