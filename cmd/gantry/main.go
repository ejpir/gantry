package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/ejpir/gantry/internal/dashboard"
	"github.com/ejpir/gantry/internal/mcpworker"
	"github.com/ejpir/gantry/internal/networkworker"
	"github.com/ejpir/gantry/internal/policyservice"
	"github.com/ejpir/gantry/internal/remote"
	"github.com/ejpir/gantry/internal/runvm"
	"github.com/ejpir/gantry/internal/sandbox"
	"github.com/ejpir/gantry/internal/sandbox/controlcmd"
	"github.com/ejpir/gantry/internal/sandbox/dashboardsvc"
	"github.com/ejpir/gantry/internal/selfupdate"
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
  gantry apply -f gantry.yaml       # create or reconcile from a manifest
  gantry manifest <verb>            # validate or export sandbox manifests
  gantry configure <name> [flags]   # update SSH, Dev Containers, and resources
  gantry exec <name> [-- CMD]       # attach a shell to a running sandbox
  gantry ls                         # list sandboxes
  gantry audit <name>               # security-event trail (credentials, secrets, custody)
  gantry mcp <name> [tools]         # MCP gateway: configured servers; live tool list
  gantry ssh NAME [-- CMD]          # SSH through the sandbox-local socket
  gantry tui                        # interactive local sandbox dashboard
  gantry serve                      # manager API and optional organization-wide mTLS policy feed
  gantry remote <verb>              # remote manager profiles: add|ls|rm|test
  gantry pi [flags] [-- PI_ARGS]    # run the pi coding agent inside a sandbox
  gantry image <verb>               # OCI images: ls|pull|import|rm|prune|login|logout|credentials
  gantry share <verb>               # live host shares: add|remove|ls
  gantry ports <verb>               # host->guest port forwards: ls|publish|unpublish
  gantry net-policy <verb>          # live egress policy: set|default|show
  gantry policy <verb>              # signed org policy: generate|sign|verify|check|set|clear|show|feed-request
  gantry policy-service <verb>      # organization policy feed and admin API: init|serve|admin
  gantry org <verb>                 # host OIDC membership: login|status|logout|apply
  gantry import [<name>]            # adopt a reference-stack sandbox (list with no name)
  gantry export [options] <name>    # package a stopped sandbox as a portable OCI archive
  gantry stop <name>                # stop a sandbox
  gantry resume <name>              # boot a stopped sandbox from saved config
  gantry delete <name>              # stop + remove a sandbox
  gantry version                    # show this and the latest Gantry release
  gantry update                     # update Gantry in place

-image accepts an OCI reference (debian:bookworm-slim,
ghcr.io/org/app@sha256:...), an OCI layout directory/archive, a Docker save
tar, or a plain .erofs file. Examples:
  gantry start dev -image alpine:latest
  gantry exec -image debian:bookworm-slim -- /bin/sh
  gantry image pull ghcr.io/org/app:latest
  gantry export dev -o dev.oci.tar
  gantry image import dev.oci.tar
Run 'gantry start --help' or 'gantry exec --help' for all flags.

Remote managers: start, exec, ls, stop, delete, and resume accept
-remote NAME (or GANTRY_REMOTE) to run against a manager served with
gantry serve -listen tls://... — see docs/gantry/remote-access.md.
`)
}

func main() {
	selfupdate.CleanupRetired()
	args := os.Args[1:]
	check := startUpdateCheck(args)
	status := runMain(args)
	maybeNotifyUpdate(args, status, check)
	os.Exit(status)
}

func runMain(args []string) int {
	if len(args) == 0 {
		if term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd())) {
			return dashboard.Run(dashboardsvc.NewDashboardService(sandbox.NewLifecycleService()))
		}
		writeMainHelp(os.Stderr)
		return 2
	}

	// Accept the selector before the command as well as among verb flags.
	if remote.FlagPresent(args[:1]) {
		count := 1
		if args[0] == "-remote" || args[0] == "--remote" {
			count = 2
		}
		if len(args) <= count {
			fmt.Fprintln(os.Stderr, "usage: gantry -remote NAME COMMAND [args]")
			return 2
		}
		args = append(append([]string{args[count]}, args[:count]...), args[count+1:]...)
	}
	command, argv := args[0], args[1:]
	// Remote dispatch (docs/remote-sandbox-access.md milestone 2):
	// -remote/--remote NAME or GANTRY_REMOTE routes lifecycle verbs to a
	// remote manager. Verbs without a remote implementation fail loudly on
	// an explicit -remote rather than silently acting on the local host.
	if remote.VerbSupported(command) {
		target, rest, err := remote.ExtractTarget(argv, os.Getenv("GANTRY_REMOTE"))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		if target != "" {
			return remote.RunVerb(command, target, rest)
		}
		argv = rest
	} else if remote.FlagPresent(argv) {
		// Deny by default: adding a new local verb cannot accidentally make
		// an explicitly remote request fall through to local execution.
		target, rest, err := remote.ExtractTarget(argv, "")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		if target != "" {
			fmt.Fprintf(os.Stderr, "gantry: -remote %q is not supported for %q (see docs/gantry/remote-access.md)\n", target, command)
			return 2
		}
		// Explicitly empty is a deliberate local request, not a fallback.
		argv = rest
	}
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
	case "remote":
		return remote.Cmd(argv)
	case "version":
		return cmdVersion(argv)
	case "update":
		return cmdUpdate(argv)
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
	case "_whpx-worker":
		// Hidden Windows-only broker for the process-local WHPX partition.
		// Device emulation remains in the AppContainer VMM worker.
		return vmm.WHPXBrokerMain()
	case "_mcp-worker":
		// Hidden capability-limited MCP parser and policy worker. Host paths,
		// destinations, credentials, and guest argv remain supervisor-owned.
		return mcpworker.Cmd()
	case "_mc-spike":
		// Hidden spike role (docs/kubernetes-runtimeclass.md Phase K0):
		// boot one VM and verify multi-container guest support.
		return sandbox.CmdMCSpike(argv)
	case "_rootfs-spike":
		// Hidden spike role (docs/kubernetes-runtimeclass.md Phase K0):
		// export a host snapshot through the share hub as a guest rootfs.
		return sandbox.CmdRootfsSpike(argv)
	case "ls":
		return sandbox.CmdLs()
	case "audit":
		if len(argv) != 1 {
			fmt.Fprintln(os.Stderr, "usage: gantry audit <name>")
			return 2
		}
		lines, err := controlcmd.AuditTail(argv[0])
		if err != nil {
			fmt.Fprintln(os.Stderr, "gantry audit:", err)
			return 1
		}
		for _, line := range lines {
			fmt.Println(line)
		}
		return 0
	case "tui":
		return dashboard.Run(dashboardsvc.NewDashboardService(sandbox.NewLifecycleService()))
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
	case "apply":
		return sandbox.CmdApply(argv), true
	case "manifest":
		return sandbox.CmdManifest(argv), true
	case "configure":
		return controlcmd.CmdConfigure(argv), true
	case "pi":
		return sandbox.CmdPi(argv), true
	case "pi-serve":
		return sandbox.CmdPiServe(argv), true
	case "image":
		return sandbox.CmdImage(argv), true
	case "share":
		return controlcmd.CmdShare(argv), true
	case "mcp":
		return sandbox.CmdMCP(argv), true
	case "ssh":
		return sandbox.CmdSSH(argv), true
	case "ssh-proxy":
		return sandbox.CmdSSHProxy(argv), true
	case "ssh-known-hosts":
		return sandbox.CmdSSHKnownHosts(argv), true
	case "ports":
		return controlcmd.CmdPorts(argv), true
	case "net-policy":
		return controlcmd.CmdNetworkPolicy(argv), true
	case "policy":
		return controlcmd.CmdPolicyWithRollout(argv, sandbox.RolloutOrganizationPolicy), true
	case "org":
		return controlcmd.CmdOrg(argv), true
	case "policy-service":
		return policyservice.Cmd(argv), true
	case "import":
		return sandbox.CmdImport(argv), true
	case "export":
		return sandbox.CmdExport(argv), true
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
	request := runvm.BindFlags(run)
	kernel, initrd, rootfs := &request.Kernel, &request.Initrd, &request.Rootfs
	netEndpoint, netMACArg := &request.NetworkEndpoint, &request.NetworkMAC
	netVFKIT, netDHCP := request.NetworkVFKIT, request.NetworkDHCP
	vsockFwd, guestCID, vsockListen := &request.VsockForward, &request.GuestCID, request.VsockListen
	memMB, vcpus, append_ := &request.MemoryMiB, &request.CPUs, &request.CommandLine
	if err := run.Parse(argv); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if run.NArg() != 0 || *kernel == "" || (*initrd == "" && *rootfs == "") {
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
	hostShares, err := shares.ParseSpecs(request.Shares)
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
	for _, d := range request.Disks {
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
		cmdline = vmm.WithDeferredSMP(cmdline, *vcpus, memBytes)
	}

	var listenPorts []uint32
	if *vsockFwd != "" && *vsockListen != "" {
		listenPorts, err = parseListenPorts(*vsockListen)
		if err != nil {
			fmt.Fprintln(os.Stderr, "gantry run: -vsocklisten:", err)
			return 2
		}
	}
	var vsockFwdIdentity *sharefs.Identity
	if len(hostShares) != 0 {
		canonicalVsockFwd, identity, err := prepareRunVsockForward(*vsockFwd)
		if err != nil {
			fmt.Fprintln(os.Stderr, "gantry run: prepare vsock forwarding:", err)
			return 1
		}
		*vsockFwd = canonicalVsockFwd
		vsockFwdIdentity = identity
	}
	filesystems, err := prepareRunFilesystems(hostShares, vsockFwdIdentity)
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

func prepareRunVsockForward(path string) (string, *sharefs.Identity, error) {
	if path == "" {
		return "", nil, nil
	}
	if err := os.MkdirAll(path, 0o755); err != nil {
		return "", nil, err
	}
	identity, err := sharefs.Identify(path)
	if err != nil {
		return "", nil, err
	}
	return identity.Path(), &identity, nil
}

func prepareRunFilesystems(specs []shares.Spec, vsockFwd *sharefs.Identity) (filesystems []vmm.Filesystem, resultErr error) {
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
	identities := make([]sharefs.Identity, 0, len(specs))
	for _, spec := range specs {
		server, err := sharefs.NewServer(spec.Tag, spec.Path, spec.RO)
		if err != nil {
			resultErr = fmt.Errorf("%s: %w", spec.Tag, err)
			return
		}
		if vsockFwd != nil && server.Identity().Overlaps(*vsockFwd) {
			resultErr = fmt.Errorf("%s: share root %s overlaps vsock forwarding directory %s", spec.Tag, server.Root(), vsockFwd.Path())
			if err := server.Close(); err != nil {
				resultErr = errors.Join(resultErr, err)
			}
			return
		}
		for index, existing := range identities {
			if server.Identity().Overlaps(existing) {
				resultErr = fmt.Errorf("%s: share root %s overlaps share %s", spec.Tag, server.Root(), filesystems[index].Tag)
				if err := server.Close(); err != nil {
					resultErr = errors.Join(resultErr, err)
				}
				return
			}
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
		identities = append(identities, server.Identity())
	}
	return filesystems, nil
}

func parseListenPorts(value string) ([]uint32, error) { return runvm.ParseListenPorts(value) }
