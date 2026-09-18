package sandbox

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/ejpir/gantry/internal/gutil"
	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/layout"
	"github.com/ejpir/gantry/internal/sandbox/lifecycle"
	sandboxmanifest "github.com/ejpir/gantry/internal/sandbox/manifest"
)

// CmdManifest implements validation and redacted projection of the public
// sandbox manifest format.
func CmdManifest(argv []string) int {
	usage := func() {
		fmt.Fprintln(os.Stderr, `usage:
  gantry manifest validate FILE
  gantry manifest export NAME

validate strictly checks one versioned manifest without creating a sandbox.
export writes a redacted manifest to stdout; secret values are never exported.`)
	}
	if len(argv) == 0 || argv[0] == "-h" || argv[0] == "--help" {
		usage()
		if len(argv) == 0 {
			return 2
		}
		return 0
	}
	switch argv[0] {
	case "validate":
		if len(argv) != 2 {
			usage()
			return 2
		}
		compiled, err := loadSandboxManifest(argv[1], os.Stdin)
		if err != nil {
			fmt.Fprintln(os.Stderr, "gantry manifest validate:", err)
			return 1
		}
		fmt.Printf("manifest valid: sandbox %q (%s)\n", compiled.Document.Metadata.Name, compiled.Document.APIVersion)
		return 0
	case "export":
		if len(argv) != 2 {
			usage()
			return 2
		}
		if err := layout.ValidateName(argv[1]); err != nil {
			fmt.Fprintln(os.Stderr, "gantry manifest export:", err)
			return 2
		}
		cfg, err := config.ReadSandboxConfig(layout.Dir(argv[1]))
		if err != nil {
			fmt.Fprintln(os.Stderr, "gantry manifest export:", err)
			return 1
		}
		document, err := sandboxmanifest.FromConfig(argv[1], cfg)
		if err != nil {
			fmt.Fprintln(os.Stderr, "gantry manifest export:", err)
			return 1
		}
		raw, err := sandboxmanifest.Marshal(document)
		if err != nil {
			fmt.Fprintln(os.Stderr, "gantry manifest export:", err)
			return 1
		}
		if _, err := os.Stdout.Write(raw); err != nil {
			fmt.Fprintln(os.Stderr, "gantry manifest export:", err)
			return 1
		}
		return 0
	default:
		usage()
		return 2
	}
}

// CmdApply reconciles one local sandbox to a public manifest. Applying a
// changed running sandbox performs an orderly stop and restart; unchanged
// running sandboxes are left untouched. --check reports the action only.
func CmdApply(argv []string) int {
	flags := flag.NewFlagSet("apply", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	var path string
	flags.StringVar(&path, "f", "", "sandbox manifest path, or - for stdin")
	flags.StringVar(&path, "file", "", "sandbox manifest path, or - for stdin")
	check := flags.Bool("check", false, "validate and report reconciliation without changing state")
	force := flags.Bool("force", false, "reapply even when the manifest digest is unchanged")
	flags.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: gantry apply -f FILE [--check] [--force]")
		flags.PrintDefaults()
	}
	if err := flags.Parse(argv); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if path == "" || flags.NArg() != 0 {
		flags.Usage()
		return 2
	}
	compiled, err := loadSandboxManifest(path, os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gantry apply:", err)
		return 1
	}
	name := compiled.Document.Metadata.Name
	plan, current, err := planManifestApply(name, compiled.Options.Manifest, *force)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gantry apply:", err)
		return 1
	}
	if *check {
		fmt.Printf("sandbox %q: %s\n", name, plan.description())
		return 0
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	progress := gutil.NewProgressPrinter(os.Stdout, "gantry apply: ")
	defer progress.Finish()
	observer := cliStartObserver(progress, os.Stdout, os.Stderr)
	service := sandboxLifecycle{}
	switch plan {
	case manifestUnchanged:
		progress.Finish()
		fmt.Printf("gantry apply: sandbox %q is up to date\n", name)
		return 0
	case manifestStartSaved:
		_, err = service.Start(ctx, lifecycle.StartRequest{Name: name, Mode: lifecycle.Resume}, observer)
	case manifestCreate:
		_, err = service.Start(ctx, lifecycle.StartRequest{Name: name, Mode: lifecycle.Create, Options: compiled.Options}, observer)
	case manifestUpdateStopped:
		_, err = applySavedManifest(ctx, name, compiled.Options, observer)
	case manifestRestart:
		progress.Finish()
		fmt.Printf("gantry apply: stopping sandbox %q to reconcile manifest changes\n", name)
		if err = stopSandbox(name); err == nil {
			_, err = applySavedManifest(ctx, name, compiled.Options, observer)
			if err != nil && current != nil {
				rollbackErr := restoreAppliedSandbox(ctx, name, *current, observer)
				if rollbackErr != nil {
					err = errors.Join(err, fmt.Errorf("restore previous sandbox: %w", rollbackErr))
				}
			}
		}
	}
	if err != nil {
		progress.Finish()
		fmt.Fprintln(os.Stderr, "gantry apply:", err)
		return 1
	}
	progress.Finish()
	fmt.Printf("gantry apply: sandbox %q reconciled\n", name)
	return 0
}

func loadSandboxManifest(path string, stdin io.Reader) (sandboxmanifest.Compiled, error) {
	if path != "-" {
		return sandboxmanifest.Load(path)
	}
	baseDir, err := os.Getwd()
	if err != nil {
		return sandboxmanifest.Compiled{}, err
	}
	return sandboxmanifest.Decode(stdin, baseDir)
}

type manifestApplyPlan uint8

const (
	manifestCreate manifestApplyPlan = iota
	manifestUnchanged
	manifestStartSaved
	manifestUpdateStopped
	manifestRestart
)

func (plan manifestApplyPlan) description() string {
	switch plan {
	case manifestCreate:
		return "would create and start"
	case manifestUnchanged:
		return "up to date"
	case manifestStartSaved:
		return "would start saved configuration"
	case manifestUpdateStopped:
		return "would update and start"
	case manifestRestart:
		return "would stop, update, and restart"
	default:
		return "unknown plan"
	}
}

func planManifestApply(name string, desired *config.ManifestProvenance, force bool) (manifestApplyPlan, *config.RunConfig, error) {
	cfg, err := config.ReadSandboxConfig(layout.Dir(name))
	if errors.Is(err, os.ErrNotExist) {
		return manifestCreate, nil, nil
	}
	if err != nil {
		return manifestCreate, nil, err
	}
	alive := false
	if _, alive = layout.PID(name); !alive {
		alive = layout.LockHeld(layout.Dir(name))
	}
	matches := !force && desired != nil && cfg.Manifest != nil &&
		desired.APIVersion == cfg.Manifest.APIVersion && desired.Digest == cfg.Manifest.Digest
	if matches && alive {
		return manifestUnchanged, &cfg, nil
	}
	if matches {
		return manifestStartSaved, &cfg, nil
	}
	if alive {
		return manifestRestart, &cfg, nil
	}
	return manifestUpdateStopped, &cfg, nil
}

// applySavedManifest resolves and publishes a changed configuration without
// deleting the existing state directory. The caller must have stopped the
// sandbox first. Keeping the directory preserves audit and diagnostic state,
// unlike the historical imperative `start` replacement path.
func applySavedManifest(ctx context.Context, name string, options config.RunOptions, observer lifecycle.Observer) (lifecycle.StartResult, error) {
	result := lifecycle.StartResult{Name: name}
	lock, err := holdSandboxLaunchLock(name)
	if err != nil {
		return result, err
	}
	defer func() { _ = lock.Close() }()
	if _, alive := layout.PID(name); alive || layout.LockHeld(layout.Dir(name)) {
		return result, fmt.Errorf("%w: %q", lifecycle.ErrAlreadyRunning, name)
	}
	before, err := config.ReadSandboxConfig(layout.Dir(name))
	if err != nil {
		return result, err
	}
	options.Name = name
	resolved, err := resolveRunOptions(ctx, options, func(format string, args ...any) {
		observer.Emit("prepare", fmt.Sprintf(format, args...))
	}, nil, false)
	result.Warnings = resolved.Warnings
	if err != nil {
		return result, err
	}
	for _, warning := range resolved.Warnings {
		if observer != nil {
			observer(lifecycle.Progress{Phase: "prepare", Message: warning, Warning: true})
		}
	}
	if err := config.WriteSandboxConfig(layout.Dir(name), resolved.Config); err != nil {
		return result, err
	}
	result.PID, err = launchSandboxLockedCore(ctx, name, resolved.Config, resolved.Secrets, false, false, startSandboxDaemon, nil, observer)
	if err != nil {
		restoreErr := config.WriteSandboxConfig(layout.Dir(name), before)
		return result, errors.Join(err, restoreErr)
	}
	return result, nil
}

func restoreAppliedSandbox(ctx context.Context, name string, previous config.RunConfig, observer lifecycle.Observer) error {
	lock, err := holdSandboxLaunchLock(name)
	if err != nil {
		return err
	}
	if _, alive := layout.PID(name); alive || layout.LockHeld(layout.Dir(name)) {
		_ = lock.Close()
		return errors.New("failed replacement is still running; previous configuration was not restored")
	}
	if err := config.WriteSandboxConfig(layout.Dir(name), previous); err != nil {
		_ = lock.Close()
		return err
	}
	if err := lock.Close(); err != nil {
		return err
	}
	_, err = (sandboxLifecycle{}).Start(ctx, lifecycle.StartRequest{Name: name, Mode: lifecycle.Resume}, observer)
	return err
}
