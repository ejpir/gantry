package sandbox

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ejpir/gantry/internal/gutil"
	"github.com/ejpir/gantry/internal/image"
	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/layout"
	"github.com/ejpir/gantry/internal/sandbox/localsec"
	"github.com/ejpir/gantry/internal/vmm"
)

// CmdExport implements `gantry export`: package the immutable image and all
// persistent overlay changes from a stopped sandbox as a portable OCI archive.
func CmdExport(argv []string) int {
	flags := flag.NewFlagSet("export", flag.ContinueOnError)
	output := flags.String("o", "", "output OCI archive (default: NAME.oci.tar)")
	flags.StringVar(output, "output", "", "output OCI archive (default: NAME.oci.tar)")
	reference := flags.String("name", "", "local image reference stored in the archive")
	force := flags.Bool("force", false, "replace an existing output archive")
	flags.Usage = func() {
		_, _ = fmt.Fprintln(flags.Output(), `usage: gantry export [options] NAME [OUTPUT]

Package a stopped sandbox's image and persistent filesystem changes as a
portable OCI image-layout archive. Host shares are not copied. The archive may
contain credentials or other sensitive files saved inside the sandbox.

options:
  -o, --output PATH   output archive (default: NAME.oci.tar)
  --name REF          image reference (default: gantry-export/NAME:latest)
  --force             replace an existing archive`)
	}
	// The standard flag package stops at NAME. Reorder recognized options so
	// both `export -o file NAME` and the natural `export NAME -o file` work.
	var optionArgs, positional []string
	for index := 0; index < len(argv); index++ {
		argument := argv[index]
		switch argument {
		case "-o", "--output", "--name":
			if index+1 >= len(argv) {
				fmt.Fprintf(os.Stderr, "gantry export: %s needs a value\n", argument)
				return 2
			}
			optionArgs = append(optionArgs, argument, argv[index+1])
			index++
		case "--force", "-h", "--help":
			optionArgs = append(optionArgs, argument)
		default:
			if strings.HasPrefix(argument, "-") {
				optionArgs = append(optionArgs, argument)
			} else {
				positional = append(positional, argument)
			}
		}
	}
	if err := flags.Parse(append(optionArgs, positional...)); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() < 1 || flags.NArg() > 2 || (flags.NArg() == 2 && *output != "") {
		flags.Usage()
		return 2
	}
	name := flags.Arg(0)
	if flags.NArg() == 2 {
		*output = flags.Arg(1)
	}
	if err := ValidateSandboxName(name); err != nil {
		fmt.Fprintln(os.Stderr, "gantry export:", err)
		return 2
	}
	if *output == "" {
		*output = name + ".oci.tar"
	}
	if *reference == "" {
		*reference = defaultExportReference(name)
	}

	fmt.Fprintln(os.Stderr, "WARNING: the exported image includes every file persisted inside the sandbox and may contain credentials; review it before sharing.")
	progress := gutil.NewProgressPrinter(os.Stdout, "gantry export: ")
	result, err := exportSandbox(name, *output, *reference, *force, progress.Printf)
	progress.Finish()
	if err != nil {
		fmt.Fprintln(os.Stderr, "gantry export:", err)
		return 1
	}
	fmt.Printf("gantry export: wrote %s (%s, %s)\n", *output, gutil.HumanSize(result.Size), result.ManifestDigest)
	fmt.Printf("gantry export: import with `gantry image import %s`\n", *output)
	return 0
}

func defaultExportReference(name string) string {
	var slug strings.Builder
	separator := false
	for _, character := range strings.ToLower(name) {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' {
			if separator && slug.Len() > 0 {
				slug.WriteByte('-')
			}
			slug.WriteRune(character)
			separator = false
		} else {
			separator = true
		}
	}
	if slug.Len() == 0 {
		slug.WriteString("sandbox")
	}
	return "gantry-export/" + slug.String() + ":latest"
}

func exportSandbox(name, output, reference string, force bool, logf func(string, ...any)) (*image.ExportResult, error) {
	launchLock, err := layout.HoldLaunchLock(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = launchLock.Close() }()
	if _, running := layout.PID(name); running {
		return nil, fmt.Errorf("sandbox %q is running; stop it before export so its filesystem is consistent", name)
	}
	cfg, err := config.ReadSandboxConfig(layout.Dir(name))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("sandbox %q does not exist", name)
		}
		return nil, fmt.Errorf("read sandbox %q: %w", name, err)
	}

	base := cfg.Image
	var extras []string
	if cfg.LayerSet != nil {
		if err := cfg.LayerSet.Validate(); err != nil {
			return nil, err
		}
		base = cfg.LayerSet.FSMeta
		extras = append([]string(nil), cfg.LayerSet.Layers...)
	}
	if base == "" {
		return nil, fmt.Errorf("sandbox %q has no exportable OCI/EROFS image", name)
	}
	if info, err := os.Stat(base); err != nil || info.IsDir() {
		if err == nil {
			err = errors.New("path is a directory")
		}
		return nil, fmt.Errorf("sandbox base image %s: %w", base, err)
	}

	var rwLayer *os.File
	if cfg.RW {
		if cfg.RWLayer == "" {
			return nil, fmt.Errorf("sandbox %q is writable but has no persistent layer", name)
		}
		info, err := gutil.ProbeExt4(cfg.RWLayer)
		if err != nil {
			return nil, fmt.Errorf("inspect writable layer: %w", err)
		}
		if info.ErrorCount > 0 {
			return nil, fmt.Errorf("writable layer is damaged: %s", info.Diagnosis())
		}
		if info.State&1 == 0 {
			return nil, fmt.Errorf("writable layer is not cleanly unmounted; resume and stop sandbox %q before exporting", name)
		}
		rwLayer, err = os.OpenFile(cfg.RWLayer, os.O_RDWR, 0)
		if err != nil {
			return nil, fmt.Errorf("open writable layer: %w", err)
		}
		defer func() { _ = rwLayer.Close() }()
		if _, err := gutil.TryLockFD(rwLayer); err != nil {
			return nil, fmt.Errorf("writable layer is in use by another process; stop every sandbox that attaches it: %w", err)
		}
	}

	kernel, err := os.Open(cfg.Kernel)
	if err != nil {
		return nil, fmt.Errorf("open sandbox kernel: %w", err)
	}
	architecture, archErr := vmm.KernelArchFile(kernel)
	closeErr := kernel.Close()
	if archErr != nil {
		return nil, archErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	absoluteOutput, err := filepath.Abs(output)
	if err != nil {
		return nil, fmt.Errorf("resolve output path: %w", err)
	}
	result, err := image.ExportOCI(image.ExportOptions{
		Output:       absoluteOutput,
		Reference:    reference,
		Architecture: architecture,
		Base:         base,
		Extras:       extras,
		RWLayer:      rwLayer,
		Config:       cfg.ImageCfg,
		Force:        force,
		Logf:         logf,
	})
	if err != nil {
		return nil, err
	}
	// The archive may contain persisted credentials. On Windows, mode 0600
	// alone does not establish a private ACL, so harden and verify the DACL
	// before reporting a usable export.
	if err := localsec.SecureEndpoint(absoluteOutput); err != nil {
		_ = os.Remove(absoluteOutput)
		return nil, fmt.Errorf("secure exported archive: %w", err)
	}
	return result, nil
}
