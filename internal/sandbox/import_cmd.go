package sandbox

// import_cmd.go — `gantry import`: adopt a sandbox from the reference
// stack's state directory. Immutable image content never moves — the guest
// attaches the snapshotter's native multi-device erofs layer set. The ext4
// upper is cloned into Gantry's private store so the two runtimes never write
// the same filesystem. Workspace, ports, service domains and container config
// are mapped onto Gantry's own sandbox.json.

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/ejpir/gantry/internal/atomicfile"
	"github.com/ejpir/gantry/internal/guestasset"
	"github.com/ejpir/gantry/internal/gutil"
	"github.com/ejpir/gantry/internal/image"
)

// CmdImport implements `gantry import`.
func CmdImport(argv []string) int {
	fs := flag.NewFlagSet("import", flag.ExitOnError)
	root := fs.String("root", dockerSandboxesRoot(), "reference sandbox daemon state dir (env: GANTRY_DOCKER_SBX_ROOT)")
	as := fs.String("as", "", "gantry sandbox name (default: the source runtime name)")
	dryRun := fs.Bool("dry-run", false, "print the resolved gantry configuration without starting anything")
	logPath := fs.String("log", "", "daemon.log path (default: <root>/daemon.log)")
	workspaceOwner := fs.String("workspace-owner", "auto", "guest-visible workspace owner: auto | host | UID:GID")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, `usage: gantry import [<name>] [flags]

Import a sandbox from the reference sandbox stack: list with no name,
adopt with one. Immutable image layers attach natively (multi-device
erofs); the writable ext4 layer is cloned privately. Nothing is pulled
or flattened.

examples:
  gantry import                       # list discoverable sandboxes
  gantry import codex-dev --dry-run   # show what would be adopted
  gantry import codex-dev             # adopt and start
  gantry import codex-dev --workspace-owner 1000:1000

flags:`)
		fs.PrintDefaults()
	}
	if len(argv) > 0 && (argv[0] == "-h" || argv[0] == "--help") {
		fs.Usage()
		return 0
	}
	args := []string{}
	rest := []string{}
	for i, a := range argv {
		if !strings.HasPrefix(a, "-") && i == 0 {
			args = append(args, a)
		} else {
			rest = append(rest, a)
		}
	}
	_ = fs.Parse(rest)

	if len(args) == 0 {
		return listDockerSandboxes(*root)
	}
	return importDockerSandbox(*root, args[0], *as, *logPath, *workspaceOwner, *dryRun)
}

func listDockerSandboxes(root string) int {
	entries, err := filepath.Glob(filepath.Join(root, "runtimes", "*.json"))
	if err != nil || len(entries) == 0 {
		fmt.Fprintf(os.Stderr, "gantry import: no sandboxes found under %s\n", root)
		return 1
	}
	w := newCLITable(os.Stdout)
	_, _ = fmt.Fprintln(w, "SANDBOX\tIMAGE\tWORKSPACE\tPORTS")
	names := []string{}
	byName := map[string]string{}
	for _, e := range entries {
		byName[filepath.Base(e)] = e
	}
	for base := range byName {
		names = append(names, base)
	}
	sort.Strings(names)
	for _, base := range names {
		b, err := os.ReadFile(byName[base])
		if err != nil {
			continue
		}
		rt, err := parseDockerRuntime(b)
		if err != nil {
			continue
		}
		ports := "-"
		if pb, err := os.ReadFile(filepath.Join(root, "runtimes", "ports", sha256Hex(rt.Spec.RuntimeName)+".json")); err == nil {
			if specs, err := parseDockerPorts(pb); err == nil && len(specs) > 0 {
				ports = strings.Join(specs, ",")
			}
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", rt.Spec.RuntimeName, rt.Spec.Template, rt.Spec.WorkspaceDir, ports)
	}
	_ = w.Flush()
	_, _ = fmt.Fprintln(os.Stdout)
	writeImportCommands(os.Stdout)
	return 0
}

func writeImportCommands(output io.Writer) {
	w := newCLITable(output)
	_, _ = fmt.Fprintln(w, "COMMAND\tDESCRIPTION")
	_, _ = fmt.Fprintln(w, "gantry import <name>\tImport and start a discovered sandbox")
	_, _ = fmt.Fprintln(w, "gantry import <name> --dry-run\tPreview the resolved configuration without changing anything")
	_, _ = fmt.Fprintln(w, "gantry import <name> --as <new-name>\tImport under a different Gantry sandbox name")
	_, _ = fmt.Fprintln(w, "gantry import <name> --workspace-owner <owner>\tChoose auto, host, or UID:GID ownership")
	_, _ = fmt.Fprintln(w, "gantry import --help\tShow every flag and example")
	_ = w.Flush()
}

type dockerImportPlan struct {
	sourceName    string
	targetName    string
	runtimePath   string
	socketPath    string
	sourceRWLayer string
	rwLayer       string
	runtime       *dockerRuntime
	config        RunConfig
}

func importDockerSandbox(root, name, as, logPath, workspaceOwner string, dryRun bool) int {
	plan, err := inspectDockerImport(root, name, as, logPath, workspaceOwner)
	if err != nil {
		return reportImportError(err)
	}

	// Probe and clone under an exclusive flock on the SOURCE rwlayer. The
	// lock serializes us against other gantry attaches (our vblk layer
	// takes the same lock); it cannot stop a non-cooperative writer, so
	// the container state is re-checked right before the clone to narrow
	// the window where the reference stack restarts mid-import.
	sourceLock, err := lockImportedRWLayer(plan.sourceRWLayer)
	if err != nil {
		return reportImportError(err)
	}
	defer func() { _ = sourceLock.Close() }()

	progress := gutil.NewProgressPrinter(os.Stdout, "gantry import: ")
	err = plan.prepare(root, progress.Printf)
	progress.Finish()
	if err != nil {
		return reportImportError(err)
	}

	if dryRun {
		plan.printDryRun()
		return 0
	}

	if err := plan.cloneWritableLayer(); err != nil {
		return reportImportError(err)
	}
	plan.printAdoption()
	return launchSandbox(plan.targetName, plan.config, nil, true)
}

func reportImportError(err error) int {
	fmt.Fprintf(os.Stderr, "gantry import: %v\n", err)
	return 1
}

func inspectDockerImport(root, name, as, logPath, workspaceOwner string) (*dockerImportPlan, error) {
	runtimePath := filepath.Join(root, "runtimes", name+".json")
	b, err := os.ReadFile(runtimePath)
	if err != nil {
		return nil, err
	}
	runtimeConfig, err := parseDockerRuntime(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", runtimePath, err)
	}
	targetName := as
	if targetName == "" {
		targetName = runtimeConfig.Spec.RuntimeName
	}
	if !validSandboxName(targetName) {
		return nil, fmt.Errorf("invalid sandbox name %q", targetName)
	}

	// The live lookup supplies both the log-attribution ID and the process
	// configuration to reproduce in Gantry.
	socketPath := filepath.Join(root, "docker.sock")
	container, err := dockerFindContainer(socketPath, name)
	if err != nil {
		return nil, err
	}
	if !dockerSourceQuiescent(container.State) {
		return nil, fmt.Errorf("source sandbox %q is %s; stop it before importing its writable layer", name, container.State)
	}
	imageConfig, err := dockerImageConfig(socketPath, container.ID)
	if err != nil {
		return nil, fmt.Errorf("inspect: %w", err)
	}
	ownerSuffix, err := importedWorkspaceOwner(workspaceOwner, imageConfig)
	if err != nil {
		return nil, fmt.Errorf("--workspace-owner: %w", err)
	}

	if logPath == "" {
		logPath = filepath.Join(root, "daemon.log")
	}
	logText, err := os.ReadFile(logPath)
	if err != nil {
		return nil, err
	}
	layers, sourceRWLayer, err := parseTaskRootfs(string(logText), container.ID)
	if err != nil {
		return nil, err
	}
	if err := layers.Validate(); err != nil {
		return nil, err
	}

	var shareSpecs []string
	if runtimeConfig.Spec.WorkspaceDir != "" {
		workspace := runtimeConfig.Spec.WorkspaceDir
		shareSpecs = append(shareSpecs, "workspace="+workspace+"@"+workspace+ownerSuffix)
	}
	rwLayer := defaultRWLayerPath(targetName)
	return &dockerImportPlan{
		sourceName:    name,
		targetName:    targetName,
		runtimePath:   runtimePath,
		socketPath:    socketPath,
		sourceRWLayer: sourceRWLayer,
		rwLayer:       rwLayer,
		runtime:       runtimeConfig,
		config: RunConfig{
			ImageRef: runtimeConfig.Spec.Template,
			ImageCfg: imageConfig,
			LayerSet: layers,
			RWLayer:  rwLayer,
			RW:       true,
			Shares:   shareSpecs,
			Net:      true,
			MemMB:    512,
			VCPUs:    1,
		},
	}, nil
}

func lockImportedRWLayer(path string) (*os.File, error) {
	lock, err := gutil.TryLockFile(path)
	if err != nil {
		return nil, fmt.Errorf("source writable layer is locked by another gantry process: %w", err)
	}
	info, err := gutil.ProbeExt4(path)
	if err != nil {
		_ = lock.Close()
		return nil, fmt.Errorf("writable layer: %w", err)
	}
	if info.State&gutil.Ext4StateError != 0 {
		_ = lock.Close()
		return nil, fmt.Errorf("source writable layer is damaged: %s (repair it offline before importing)", info.Diagnosis())
	}
	return lock, nil
}

func (p *dockerImportPlan) prepare(root string, say func(string, ...any)) error {
	ports, err := loadImportedPorts(root, p.sourceName)
	if err != nil {
		return err
	}
	kernel, rootfs, err := ensureImportedGuestAssets(say)
	if err != nil {
		return err
	}
	netpolPath, err := writeImportedNetpol(p.runtime, p.targetName)
	if err != nil {
		return err
	}
	p.config.Kernel = kernel
	p.config.Rootfs = rootfs
	p.config.Ports = ports
	p.config.NetPol = netpolPath
	return nil
}

func loadImportedPorts(root, name string) ([]string, error) {
	path := filepath.Join(root, "runtimes", "ports", sha256Hex(name)+".json")
	b, err := os.ReadFile(path)
	if err != nil {
		// The source stack does not create this optional file when the
		// sandbox has no published ports.
		return nil, nil
	}
	specs, err := parseDockerPorts(b)
	if err != nil {
		return nil, fmt.Errorf("ports: %w", err)
	}
	ports := make([]string, 0, len(specs))
	for _, spec := range specs {
		normalized, err := NormalizePortSpec(spec)
		if err != nil {
			return nil, fmt.Errorf("port %q: %w", spec, err)
		}
		ports = append(ports, normalized)
	}
	return ports, nil
}

func ensureImportedGuestAssets(say func(string, ...any)) (string, string, error) {
	// Absolute paths are required because the daemon runs with cwd=/.
	kernel, err := guestasset.EnsureKernel(guestasset.DefaultKernel(), say)
	if err != nil {
		return "", "", err
	}
	rootfs, err := guestasset.EnsureRootfs(guestasset.DefaultRootfs(), say)
	if err != nil {
		return "", "", err
	}
	return absPath(kernel), absPath(rootfs), nil
}

func writeImportedNetpol(runtimeConfig *dockerRuntime, targetName string) (string, error) {
	policy, _ := importedNetpol(runtimeConfig)
	if policy == nil {
		return "", nil
	}
	// Keep imported policy outside the sandbox directory: launchSandbox
	// removes and recreates that directory on start.
	dir := filepath.Join(filepath.Dir(sandboxRoot()), "netpol")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, "imported-"+targetName+".json")
	if err := atomicfile.WriteFileDurable(path, policy, 0o600); err != nil {
		return "", err
	}
	return path, nil
}

func (p *dockerImportPlan) cloneWritableLayer() error {
	// Last-moment state re-check: a source that restarted since inspection
	// would be writing to the layer we are about to clone.
	container, err := dockerFindContainer(p.socketPath, p.sourceName)
	if err != nil {
		return err
	}
	if !dockerSourceQuiescent(container.State) {
		return fmt.Errorf("source sandbox %q became %s during import; stop it and retry", p.sourceName, container.State)
	}
	if err := cloneImportedRWLayer(p.sourceRWLayer, p.rwLayer); err != nil {
		return fmt.Errorf("clone writable layer: %w", err)
	}
	if err := writeRWLayerPairing(p.rwLayer, p.config.imageIdentity()); err != nil {
		return fmt.Errorf("record writable-layer pairing: %w", err)
	}
	return nil
}

func (p *dockerImportPlan) printDryRun() {
	out, _ := json.MarshalIndent(p.config, "", "  ")
	fmt.Printf("would start gantry sandbox %q from %s:\n%s\n", p.targetName, p.runtimePath, out)
}

func (p *dockerImportPlan) printAdoption() {
	fmt.Printf(
		"gantry import: adopting %q: %d shared erofs layers + private rwlayer %s\n",
		p.sourceName,
		len(p.config.LayerSet.Layers),
		filepath.Base(p.rwLayer),
	)
	if len(p.config.Ports) > 0 {
		fmt.Printf("gantry import: publishing %s\n", strings.Join(p.config.Ports, ", "))
	}
}

// importedWorkspaceOwner resolves the import-only ownership policy. "auto"
// is deliberately conservative: only a resolved/non-root image user or an
// explicit numeric user:group is trustworthy. Empty/root image users keep
// literal host ownership; images that switch users later can opt in with the
// flag instead of inheriting a guessed 1000:1000 mapping.
func importedWorkspaceOwner(value string, cfg *image.Config) (string, error) {
	switch value {
	case "", "auto":
		if cfg == nil || cfg.User == "" || cfg.User == "root" || cfg.User == "0" || cfg.User == "0:0" {
			return "", nil
		}
		if cfg.UID != 0 && cfg.GID != 0 {
			return fmt.Sprintf(",uid=%d,gid=%d", cfg.UID, cfg.GID), nil
		}
		u, g, ok := strings.Cut(cfg.User, ":")
		if !ok {
			return "", nil
		}
		uid, uerr := strconv.ParseUint(u, 10, 32)
		gid, gerr := strconv.ParseUint(g, 10, 32)
		if uerr == nil && gerr == nil {
			return fmt.Sprintf(",uid=%d,gid=%d", uid, gid), nil
		}
		return "", nil
	case "host":
		return "", nil
	default:
		u, g, ok := strings.Cut(value, ":")
		if !ok || u == "" || g == "" {
			return "", fmt.Errorf("want auto, host, or UID:GID")
		}
		uid, err := strconv.ParseUint(u, 10, 32)
		if err != nil {
			return "", fmt.Errorf("invalid UID %q", u)
		}
		gid, err := strconv.ParseUint(g, 10, 32)
		if err != nil {
			return "", fmt.Errorf("invalid GID %q", g)
		}
		return fmt.Sprintf(",uid=%d,gid=%d", uid, gid), nil
	}
}
