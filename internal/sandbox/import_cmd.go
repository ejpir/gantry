package sandbox

// import_cmd.go — `gantry import`: adopt a sandbox from the reference
// stack's state directory. The image content never moves — the guest
// attaches the snapshotter's native multi-device erofs layer set and the
// sandbox's existing ext4 writable layer — while the workspace, published
// ports, service domains and container config are mapped onto gantry's
// own sandbox.json.

import (
	"encoding/json"
	"flag"
	"fmt"
	"gantry/internal/vmm"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// CmdImport implements `gantry import`.
func CmdImport(argv []string) int {
	fs := flag.NewFlagSet("import", flag.ExitOnError)
	root := fs.String("root", dockerSandboxesRoot(), "reference sandbox daemon state dir (env: GANTRY_DOCKER_SBX_ROOT)")
	as := fs.String("as", "", "gantry sandbox name (default: the source runtime name)")
	dryRun := fs.Bool("dry-run", false, "print the resolved gantry configuration without starting anything")
	logPath := fs.String("log", "", "daemon.log path (default: <root>/daemon.log)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, `usage: gantry import [<name>] [flags]

Import a sandbox from the reference sandbox stack: list with no name,
adopt with one. The image layers and writable layer attach natively
(multi-device erofs + ext4) — nothing is exported, pulled or flattened.

examples:
  gantry import                       # list discoverable sandboxes
  gantry import codex-dev --dry-run   # show what would be adopted
  gantry import codex-dev             # adopt and start

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
	return importDockerSandbox(*root, args[0], *as, *logPath, *dryRun)
}

func listDockerSandboxes(root string) int {
	entries, err := filepath.Glob(filepath.Join(root, "runtimes", "*.json"))
	if err != nil || len(entries) == 0 {
		fmt.Fprintf(os.Stderr, "gantry import: no sandboxes found under %s\n", root)
		return 1
	}
	fmt.Printf("%-20s %-44s %-30s %s\n", "SANDBOX", "IMAGE", "WORKSPACE", "PORTS")
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
		fmt.Printf("%-20s %-44s %-30s %s\n", rt.Spec.RuntimeName, rt.Spec.Template, rt.Spec.WorkspaceDir, ports)
	}
	return 0
}

func importDockerSandbox(root, name, as, logPath string, dryRun bool) int {
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
	imgCfg, err := dockerImageConfig(sock, ctr.ID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gantry import: inspect: %v\n", err)
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
	ls, rwlayer, err := parseTaskRootfs(string(logText), ctr.ID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gantry import: %v\n", err)
		return 1
	}
	if err := ls.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "gantry import: %v\n", err)
		return 1
	}

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

	// Guest assets (auto-download on first use).
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

	// Egress policy mirroring the source service domains.
	dir := sandboxDir(gname)
	netpolPath := ""
	if pol, _ := importedNetpol(rt); pol != nil {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			fmt.Fprintf(os.Stderr, "gantry import: %v\n", err)
			return 1
		}
		netpolPath = filepath.Join(dir, "imported-netpol.json")
		if err := os.WriteFile(netpolPath, pol, 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "gantry import: %v\n", err)
			return 1
		}
	}

	var shares []string
	if rt.Spec.WorkspaceDir != "" {
		shares = append(shares, "workspace="+rt.Spec.WorkspaceDir+"@"+rt.Spec.WorkspaceDir)
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

	fmt.Printf("gantry import: adopting %q: %d erofs layers + rwlayer %s\n", name, len(ls.Layers), filepath.Base(rwlayer))
	if len(ports) > 0 {
		fmt.Printf("gantry import: publishing %s\n", strings.Join(ports, ", "))
	}
	return launchSandbox(gname, cfg, nil, true)
}
