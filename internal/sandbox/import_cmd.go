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
	"gantry/internal/gutil"
	"gantry/internal/image"
	"gantry/internal/vmm"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
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
	fs.Parse(rest)

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
	fmt.Fprintln(w, "SANDBOX\tIMAGE\tWORKSPACE\tPORTS")
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
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", rt.Spec.RuntimeName, rt.Spec.Template, rt.Spec.WorkspaceDir, ports)
	}
	_ = w.Flush()
	fmt.Fprintln(os.Stdout)
	writeImportCommands(os.Stdout)
	return 0
}

func writeImportCommands(output io.Writer) {
	w := newCLITable(output)
	fmt.Fprintln(w, "COMMAND\tDESCRIPTION")
	fmt.Fprintln(w, "gantry import <name>\tImport and start a discovered sandbox")
	fmt.Fprintln(w, "gantry import <name> --dry-run\tPreview the resolved configuration without changing anything")
	fmt.Fprintln(w, "gantry import <name> --as <new-name>\tImport under a different Gantry sandbox name")
	fmt.Fprintln(w, "gantry import <name> --workspace-owner <owner>\tChoose auto, host, or UID:GID ownership")
	fmt.Fprintln(w, "gantry import --help\tShow every flag and example")
	_ = w.Flush()
}

func importDockerSandbox(root, name, as, logPath, workspaceOwner string, dryRun bool) int {
	rtPath := filepath.Join(root, "runtimes", name+".json")
	b, err := os.ReadFile(rtPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gantry import: %v\n", err)
		return 1
	}
	rt, err := parseDockerRuntime(b)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gantry import: %s: %v\n", rtPath, err)
		return 1
	}
	gname := as
	if gname == "" {
		gname = rt.Spec.RuntimeName
	}
	if !validSandboxName(gname) {
		fmt.Fprintf(os.Stderr, "gantry import: invalid sandbox name %q\n", gname)
		return 1
	}

	// Live container lookup → container ID for the log attribution, plus
	// the container's process config.
	sock := filepath.Join(root, "docker.sock")
	ctr, err := dockerFindContainer(sock, name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gantry import: %v\n", err)
		return 1
	}
	if !dockerSourceQuiescent(ctr.State) {
		fmt.Fprintf(os.Stderr, "gantry import: source sandbox %q is %s; stop it before importing its writable layer\n", name, ctr.State)
		return 1
	}
	imgCfg, err := dockerImageConfig(sock, ctr.ID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gantry import: inspect: %v\n", err)
		return 1
	}
	ownerSuffix, err := importedWorkspaceOwner(workspaceOwner, imgCfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gantry import: --workspace-owner: %v\n", err)
		return 1
	}

	// The rootfs mount chain from the daemon log: native layer set +
	// the sandbox's own writable layer.
	if logPath == "" {
		logPath = filepath.Join(root, "daemon.log")
	}
	logText, err := os.ReadFile(logPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gantry import: %v\n", err)
		return 1
	}
	ls, sourceRWLayer, err := parseTaskRootfs(string(logText), ctr.ID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gantry import: %v\n", err)
		return 1
	}
	if err := ls.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "gantry import: %v\n", err)
		return 1
	}
	// Probe and clone under an exclusive flock on the SOURCE rwlayer. The
	// lock serializes us against other gantry attaches (our vblk layer
	// takes the same lock); it cannot stop a non-cooperative writer, so
	// the container state is re-checked right before the clone to narrow
	// the window where the reference stack restarts mid-import.
	sourceLock, err := gutil.TryLockFile(sourceRWLayer)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gantry import: source writable layer is locked by another gantry process: %v\n", err)
		return 1
	}
	defer sourceLock.Close()
	if info, err := gutil.ProbeExt4(sourceRWLayer); err != nil {
		fmt.Fprintf(os.Stderr, "gantry import: writable layer: %v\n", err)
		return 1
	} else if info.State&gutil.Ext4StateError != 0 {
		fmt.Fprintf(os.Stderr, "gantry import: source writable layer is damaged: %s (repair it offline before importing)\n", info.Diagnosis())
		return 1
	}
	// Immutable EROFS layers are safe to share, but an ext4 writable layer
	// is not. Point Gantry at its own clone so the source stack can restart
	// safely and two runtimes can never attach the same mutable filesystem.
	rwlayer := defaultRWLayerPath(gname)

	// Published ports.
	var ports []string
	if pb, err := os.ReadFile(filepath.Join(root, "runtimes", "ports", sha256Hex(name)+".json")); err == nil {
		specs, perr := parseDockerPorts(pb)
		if perr != nil {
			fmt.Fprintf(os.Stderr, "gantry import: ports: %v\n", perr)
			return 1
		}
		for _, spec := range specs {
			n, nerr := NormalizePortSpec(spec)
			if nerr != nil {
				fmt.Fprintf(os.Stderr, "gantry import: port %q: %v\n", spec, nerr)
				return 1
			}
			ports = append(ports, n)
		}
	}

	// Guest assets (auto-download on first use). Absolute paths: the
	// daemon runs with cwd=/, so anything relative would break there.
	say := func(format string, a ...any) { fmt.Printf("gantry import: "+format+"\n", a...) }
	kernel, err := vmm.EnsureKernel(vmm.DefaultKernelImage(), say)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gantry import: %v\n", err)
		return 1
	}
	rootfs, err := vmm.EnsureRootfs(vmm.DefaultRootfs(), say)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gantry import: %v\n", err)
		return 1
	}
	kernel, rootfs = absPath(kernel), absPath(rootfs)

	// Egress policy mirroring the source service domains. Written OUTSIDE
	// the sandbox dir on purpose: launchSandbox removes and recreates that
	// directory on start.
	netpolPath := ""
	if pol, _ := importedNetpol(rt); pol != nil {
		polDir := filepath.Join(filepath.Dir(sandboxRoot()), "netpol")
		if err := os.MkdirAll(polDir, 0o700); err != nil {
			fmt.Fprintf(os.Stderr, "gantry import: %v\n", err)
			return 1
		}
		netpolPath = filepath.Join(polDir, "imported-"+gname+".json")
		if err := os.WriteFile(netpolPath, pol, 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "gantry import: %v\n", err)
			return 1
		}
	}

	var shares []string
	if rt.Spec.WorkspaceDir != "" {
		shares = append(shares, "workspace="+rt.Spec.WorkspaceDir+"@"+rt.Spec.WorkspaceDir+ownerSuffix)
	}

	cfg := RunConfig{
		Kernel:   kernel,
		Rootfs:   rootfs,
		ImageRef: rt.Spec.Template,
		ImageCfg: imgCfg,
		LayerSet: ls,
		RWLayer:  rwlayer,
		RW:       true,
		Shares:   shares,
		Ports:    ports,
		Net:      true,
		NetPol:   netpolPath,
		MemMB:    512,
		VCPUs:    1,
	}

	if dryRun {
		out, _ := json.MarshalIndent(cfg, "", "  ")
		fmt.Printf("would start gantry sandbox %q from %s:\n%s\n", gname, rtPath, out)
		return 0
	}

	// Last-moment state re-check: a source that restarted since the first
	// lookup would be writing to the layer we are about to clone.
	if ctr, err := dockerFindContainer(sock, name); err != nil {
		fmt.Fprintf(os.Stderr, "gantry import: %v\n", err)
		return 1
	} else if !dockerSourceQuiescent(ctr.State) {
		fmt.Fprintf(os.Stderr, "gantry import: source sandbox %q became %s during import; stop it and retry\n", name, ctr.State)
		return 1
	}
	if err := cloneImportedRWLayer(sourceRWLayer, rwlayer); err != nil {
		fmt.Fprintf(os.Stderr, "gantry import: clone writable layer: %v\n", err)
		return 1
	}
	writeRWLayerPairing(rwlayer, cfg.imageIdentity())

	fmt.Printf("gantry import: adopting %q: %d shared erofs layers + private rwlayer %s\n", name, len(ls.Layers), filepath.Base(rwlayer))
	if len(ports) > 0 {
		fmt.Printf("gantry import: publishing %s\n", strings.Join(ports, ", "))
	}
	return launchSandbox(gname, cfg, nil, true)
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
