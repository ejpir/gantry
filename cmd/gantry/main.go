package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/ejpir/gantry/internal/dashboard"
	"github.com/ejpir/gantry/internal/gutil"
	"github.com/ejpir/gantry/internal/networkworker"
	"github.com/ejpir/gantry/internal/sandbox"
	"github.com/ejpir/gantry/internal/sharefs"
	"github.com/ejpir/gantry/internal/shares"
	"github.com/ejpir/gantry/internal/vmm"
	"github.com/ejpir/gantry/internal/vmmworker"

	"golang.org/x/term"
)

func writeMainHelp(output io.Writer) {
	_, _ = fmt.Fprint(output, `gantry — a tiny microVM monitor (KVM on Linux arm64/x86-64, HVF on macOS).

usage:
  gantry run -kernel Image -initrd artifacts/initramfs.cpio.gz   # our guest init
  gantry run -kernel artifacts/nerdbox-kernel-arm64 \
             -rootfs artifacts/nerdbox-rootfs-arm64.erofs \
             -vsockfwd /tmp/gantry-vsock               #   real nerdbox guest
  gantry exec [flags] [-- CMD]      # one-shot: boot VM + shell in one command
  gantry start <name> [flags]       # create a long-lived sandbox VM
  gantry exec <name> [-- CMD]       # attach a shell to a running sandbox
  gantry ls                         # list sandboxes
  gantry tui                        # interactive local sandbox dashboard
  gantry serve                      # local HTTP/JSON manager on ~/.gantry/manager.sock
  gantry pi [flags] [-- PI_ARGS]    # run the pi coding agent inside a sandbox
  gantry image <verb>               # OCI image cache: ls|pull|rm|prune|login|logout|credentials
  gantry share <verb>               # live host shares: add|remove|ls
  gantry ports <verb>               # host->guest port forwards: ls|publish|unpublish
  gantry net-policy <verb>          # live egress policy: set|default|show
  gantry import [<name>]            # adopt a reference-stack sandbox (list with no name)
  gantry stop <name>                # stop a sandbox
  gantry resume <name>              # boot a stopped sandbox from saved config
  gantry delete <name>              # stop + remove a sandbox

-image accepts an OCI reference (debian:bookworm-slim,
ghcr.io/org/app@sha256:...), an OCI layout dir, a docker save tar, or a
plain .erofs file. Examples:
  gantry start dev -image alpine:latest
  gantry exec -image debian:bookworm-slim -- /bin/sh
  gantry image pull ghcr.io/org/app:latest
Run 'gantry start --help' or 'gantry exec --help' for all flags.
`)
}

func main() {
	os.Exit(runMain(os.Args[1:]))
}

func runMain(args []string) int {
	if len(args) == 0 {
		if term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd())) {
			return dashboard.Run(sandbox.NewDashboardService())
		}
		writeMainHelp(os.Stderr)
		return 2
	}

	command, argv := args[0], args[1:]
	if status, ok := runSimpleCommand(command, argv); ok {
		return status
	}
	switch command {
	case "-h", "--help", "help":
		writeMainHelp(os.Stdout)
		return 0
	case "exec":
		if len(argv) > 0 && !strings.HasPrefix(argv[0], "-") {
			name, ok := validSandboxName(argv[0])
			if !ok {
				return 2
			}
			return sandbox.CmdSandboxExec(name, argv[1:])
		}
		return runExec(argv)
	case "resume":
		if len(argv) == 1 && (argv[0] == "-h" || argv[0] == "--help") {
			fmt.Fprintln(os.Stderr, "usage: gantry resume <name>   # boot from saved sandbox.json")
			return 0
		}
		if len(argv) != 1 {
			fmt.Fprintln(os.Stderr, "usage: gantry resume <name>")
			return 2
		}
		name, ok := validSandboxName(argv[0])
		if !ok {
			return 2
		}
		return sandbox.CmdResume(name)
	case "serve":
		return sandbox.CmdServe(argv)
	case "daemon":
		if len(argv) < 1 || len(argv) > 2 {
			return 2
		}
		name, ok := validSandboxName(argv[0])
		if !ok {
			return 2
		}
		readySocket := ""
		if len(argv) == 2 {
			readySocket = argv[1]
		}
		return sandbox.CmdDaemon(name, readySocket)
	case "_net-worker":
		// Hidden worker role (docs/vmm-network-isolation.md): authority is
		// the inherited bootstrap channels, never the argv.
		return networkworker.Cmd()
	case "_vmm-worker":
		// Hidden worker role (Phase 2): owns the hypervisor, guest RAM,
		// devices, and the vsock data plane.
		return vmmworker.Main()
	case "ls":
		return sandbox.CmdLs()
	case "tui":
		return dashboard.Run(sandbox.NewDashboardService())
	case "stop", "delete":
		if len(argv) != 1 {
			fmt.Fprintf(os.Stderr, "usage: gantry %s <name>\n", command)
			return 2
		}
		name, ok := validSandboxName(argv[0])
		if !ok {
			return 2
		}
		if command == "stop" {
			return sandbox.CmdStop(name)
		}
		return sandbox.CmdDelete(name)
	case "run":
		return cmdRun(argv)
	default:
		fmt.Fprintf(os.Stderr, "gantry: unknown command %q\n\n", command)
		writeMainHelp(os.Stderr)
		return 2
	}
}

func runSimpleCommand(command string, argv []string) (int, bool) {
	switch command {
	case "start":
		return sandbox.CmdStart(argv), true
	case "pi":
		return sandbox.CmdPi(argv), true
	case "pi-serve":
		return sandbox.CmdPiServe(argv), true
	case "image":
		return sandbox.CmdImage(argv), true
	case "share":
		return sandbox.CmdShare(argv), true
	case "ports":
		return sandbox.CmdPorts(argv), true
	case "net-policy":
		return sandbox.CmdNetworkPolicy(argv), true
	case "import":
		return sandbox.CmdImport(argv), true
	default:
		return 0, false
	}
}

func validSandboxName(name string) (string, bool) {
	if err := sandbox.ValidateSandboxName(name); err != nil {
		fmt.Fprintln(os.Stderr, "gantry:", err)
		return "", false
	}
	return name, true
}

func cmdRun(argv []string) int {
	run := flag.NewFlagSet("run", flag.ContinueOnError)
	kernel := run.String("kernel", "", "path to arm64 Linux kernel Image (required)")
	initrd := run.String("initrd", "", "path to initramfs cpio.gz")
	rootfs := run.String("rootfs", "", "path to rootfs image attached as virtio-blk /dev/vda (e.g. nerdbox EROFS)")
	var disks gutil.StrList
	run.Var(&disks, "disk", "extra virtio-blk image (repeatable): /dev/vdb, /dev/vdc, ...")
	var shareArgs gutil.StrList
	run.Var(&shareArgs, "share", "host directory exported through virtio-fs as TAG=PATH[@CTRPATH][,ro] (repeatable)")
	netEndpoint := run.String("net", "", "Unix datagram raw-Ethernet backend (e.g. gvproxy vfkit socket)")
	netMACArg := run.String("net-mac", "5a:94:ef:e4:0c:ee", "virtio-net MAC address")
	netVFKIT := run.Bool("net-vfkit", true, "send the VFKT registration datagram to the network backend")
	netDHCP := run.Bool("net-dhcp", true, "ask vminitd to configure the interface using DHCP")
	vsockFwd := run.String("vsockfwd", "", "host dir for vsock forwarding (sockets at <dir>/<port>.sock)")
	guestCID := run.Uint64("guestcid", 3, "guest vsock context ID")
	vsockListen := run.String("vsocklisten", "1026", "comma-separated guest ports accepting host connections (unix sockets at <vsockfwd>/listen-N.sock)")
	memMB := run.Uint("mem", 512, "guest RAM in MiB")
	vcpus := run.Int("cpus", 1, fmt.Sprintf("guest vCPU count (SMP via PSCI CPU_ON; max %d on this host)", vmm.MaxSupportedVCPUs()))
	append_ := run.String("append", "", "kernel cmdline (default depends on -rootfs)")
	if err := run.Parse(argv); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *kernel == "" || (*initrd == "" && *rootfs == "") {
		run.Usage()
		return 2
	}
	if uint64(*memMB) > vmm.MaxMemoryBytes>>20 {
		fmt.Fprintf(os.Stderr, "gantry run: memory must be at most %d MiB\n", vmm.MaxMemoryBytes>>20)
		return 2
	}
	memBytes := uint64(*memMB) << 20
	if err := vmm.ValidateResources(memBytes, *vcpus); err != nil {
		fmt.Fprintln(os.Stderr, "gantry run:", err)
		return 2
	}

	var netMAC [6]byte
	if *netEndpoint != "" {
		hw, err := net.ParseMAC(*netMACArg)
		if err != nil || len(hw) != len(netMAC) {
			fmt.Fprintf(os.Stderr, "gantry: invalid -net-mac %q\n", *netMACArg)
			return 2
		}
		copy(netMAC[:], hw)
	}
	hostShares, err := shares.ParseSpecs(shareArgs)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gantry: invalid -share:", err)
		return 2
	}

	// Boot assets are opened once, up front: the VM boots from exactly
	// the validated files (no path swap between resolution and boot).
	kernelF, err := os.Open(*kernel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gantry run: kernel %s: %v\n", *kernel, err)
		return 1
	}
	opened := []*os.File{kernelF}
	claimed := false
	defer func() {
		if claimed {
			return
		}
		for _, file := range opened {
			_ = file.Close()
		}
	}()
	var initrdF, rootfsF *os.File
	if *initrd != "" {
		if initrdF, err = os.Open(*initrd); err != nil {
			fmt.Fprintf(os.Stderr, "gantry run: initrd %s: %v\n", *initrd, err)
			return 1
		}
		opened = append(opened, initrdF)
	}
	if *rootfs != "" {
		if rootfsF, err = os.Open(*rootfs); err != nil {
			fmt.Fprintf(os.Stderr, "gantry run: rootfs %s: %v\n", *rootfs, err)
			return 1
		}
		opened = append(opened, rootfsF)
	}
	var diskFs []*os.File
	for _, d := range disks {
		f, err := os.OpenFile(d, os.O_RDWR, 0)
		if err != nil {
			fmt.Fprintf(os.Stderr, "gantry run: disk %s: %v\n", d, err)
			return 1
		}
		diskFs = append(diskFs, f)
		opened = append(opened, f)
	}

	cmdline := *append_
	if cmdline == "" {
		arch, err := vmm.KernelArchFile(kernelF)
		if err != nil {
			fmt.Fprintf(os.Stderr, "gantry run: %v\n", err)
			return 1
		}
		cmdline = vmm.DefaultCmdline(arch, *rootfs, *initrd, *guestCID, *netEndpoint, netMAC, *netDHCP)
		cmdline = vmm.WithDeferredSMP(cmdline, *vcpus)
	}

	var listenPorts []uint32
	if *vsockFwd != "" && *vsockListen != "" {
		listenPorts, err = parseListenPorts(*vsockListen)
		if err != nil {
			fmt.Fprintln(os.Stderr, "gantry run: -vsocklisten:", err)
			return 2
		}
	}
	filesystems, err := prepareRunFilesystems(hostShares)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gantry run: prepare shares:", err)
		return 1
	}

	// Prepare claims every input at entry and closes it on every return path.
	claimed = true
	m, err := vmm.Prepare(vmm.Opts{
		MemSize:     memBytes,
		Kernel:      kernelF,
		Initrd:      initrdF,
		Rootfs:      rootfsF,
		Disks:       diskFs,
		Filesystems: filesystems,
		NetEndpoint: *netEndpoint,
		NetMAC:      netMAC,
		NetVFKIT:    *netVFKIT,
		VsockFwd:    *vsockFwd,
		Interactive: true,
		VCPUs:       *vcpus,
		GuestCID:    *guestCID,
		VsockListen: listenPorts,
		Cmdline:     cmdline,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "gantry:", err)
		return 1
	}

	if *vsockFwd != "" {
		if err := shares.WriteManifest(filepath.Join(*vsockFwd, "shares.json"), hostShares); err != nil {
			fmt.Fprintf(os.Stderr, "gantry: write share manifest: %v\n", err)
		}
	}

	setRawMode()
	err = vmm.Run(m)
	restoreMode() // explicit: os.Exit skips deferred calls
	if err != nil {
		fmt.Fprintln(os.Stderr, "\ngantry:", err)
		return 1
	}
	return 0
}

func prepareRunFilesystems(specs []shares.Spec) (filesystems []vmm.Filesystem, resultErr error) {
	defer func() {
		if resultErr == nil {
			return
		}
		for _, filesystem := range filesystems {
			if filesystem.Owner != nil {
				if err := filesystem.Owner.Close(); err != nil {
					resultErr = errors.Join(resultErr, fmt.Errorf("close share %s: %w", filesystem.Tag, err))
				}
			}
		}
		filesystems = nil
	}()

	filesystems = make([]vmm.Filesystem, 0, len(specs))
	for _, spec := range specs {
		server, err := sharefs.NewServer(spec.Tag, spec.Path, spec.RO)
		if err != nil {
			resultErr = fmt.Errorf("%s: %w", spec.Tag, err)
			return
		}
		mode := ""
		if spec.RO {
			mode = " (read-only, host-enforced)"
		}
		filesystems = append(filesystems, vmm.Filesystem{
			Tag:         spec.Tag,
			Handler:     server,
			Owner:       server,
			Description: fmt.Sprintf("host %q%s", server.Root(), mode),
		})
	}
	return filesystems, nil
}

func parseListenPorts(value string) ([]uint32, error) {
	parts := strings.Split(value, ",")
	ports := make([]uint32, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		port, err := strconv.ParseUint(part, 10, 32)
		if err != nil || port == 0 {
			return nil, fmt.Errorf("invalid guest port %q", part)
		}
		ports = append(ports, uint32(port))
	}
	return ports, nil
}
