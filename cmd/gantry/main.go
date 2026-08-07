package main

import (
	"flag"
	"fmt"
	"github.com/ejpir/gantry/internal/gutil"
	"github.com/ejpir/gantry/internal/sandbox"
	"github.com/ejpir/gantry/internal/vmm"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"

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
	run := flag.NewFlagSet("run", flag.ExitOnError)
	kernel := run.String("kernel", "", "path to arm64 Linux kernel Image (required)")
	initrd := run.String("initrd", "", "path to initramfs cpio.gz")
	rootfs := run.String("rootfs", "", "path to rootfs image attached as virtio-blk /dev/vda (e.g. nerdbox EROFS)")
	var disks gutil.StrList
	run.Var(&disks, "disk", "extra virtio-blk image (repeatable): /dev/vdb, /dev/vdc, ...")
	var shares gutil.StrList
	run.Var(&shares, "share", "host directory exported through virtio-fs as TAG=PATH[@CTRPATH][,ro] (repeatable)")
	netEndpoint := run.String("net", "", "Unix datagram raw-Ethernet backend (e.g. gvproxy vfkit socket)")
	netMACArg := run.String("net-mac", "5a:94:ef:e4:0c:ee", "virtio-net MAC address")
	netVFKIT := run.Bool("net-vfkit", true, "send the VFKT registration datagram to the network backend")
	netDHCP := run.Bool("net-dhcp", true, "ask vminitd to configure the interface using DHCP")
	vsockFwd := run.String("vsockfwd", "", "host dir for vsock forwarding (sockets at <dir>/<port>.sock)")
	guestCID := run.Uint64("guestcid", 3, "guest vsock context ID")
	vsockListen := run.String("vsocklisten", "1026", "comma-separated guest ports accepting host connections (unix sockets at <vsockfwd>/listen-N.sock)")
	memMB := run.Uint("mem", 512, "guest RAM in MiB")
	vcpus := run.Int("cpus", 1, "guest vCPU count (SMP via PSCI CPU_ON; max 8)")
	append_ := run.String("append", "", "kernel cmdline (default depends on -rootfs)")

	if len(os.Args) < 2 {
		if term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd())) {
			os.Exit(sandbox.CmdTUI())
		}
		writeMainHelp(os.Stderr)
		os.Exit(2)
	}
	// mustName validates a sandbox name at the dispatch layer so every
	// name-taking subcommand (exec/start/resume/daemon/stop/delete) is covered.
	mustName := func(n string) string {
		if err := sandbox.ValidateSandboxName(n); err != nil {
			fmt.Fprintln(os.Stderr, "gantry:", err)
			os.Exit(2)
		}
		return n
	}
	switch os.Args[1] {
	case "-h", "--help", "help":
		writeMainHelp(os.Stdout)
		return
	case "exec":
		if len(os.Args) > 2 && !strings.HasPrefix(os.Args[2], "-") {
			os.Exit(sandbox.CmdSandboxExec(mustName(os.Args[2]), os.Args[3:]))
		}
		cmdExec(os.Args[2:])
		return
	case "start":
		os.Exit(sandbox.CmdStart(os.Args[2:]))
	case "resume":
		if len(os.Args) == 3 && (os.Args[2] == "-h" || os.Args[2] == "--help") {
			fmt.Fprintln(os.Stderr, "usage: gantry resume <name>   # boot from saved sandbox.json")
			return
		}
		if len(os.Args) != 3 {
			fmt.Fprintln(os.Stderr, "usage: gantry resume <name>")
			os.Exit(2)
		}
		os.Exit(sandbox.CmdResume(mustName(os.Args[2])))
	case "daemon":
		if len(os.Args) != 3 {
			os.Exit(2)
		}
		os.Exit(sandbox.CmdDaemon(mustName(os.Args[2])))
	case "_net-worker":
		// Hidden worker role (docs/vmm-network-isolation.md): authority is
		// the inherited bootstrap channels, never the argv.
		os.Exit(sandbox.CmdNetWorker())
	case "ls":
		os.Exit(sandbox.CmdLs())
	case "tui":
		os.Exit(sandbox.CmdTUI())
	case "pi":
		os.Exit(sandbox.CmdPi(os.Args[2:]))
	case "pi-serve":
		os.Exit(sandbox.CmdPiServe(os.Args[2:]))
	case "image":
		os.Exit(sandbox.CmdImage(os.Args[2:]))
	case "share":
		os.Exit(sandbox.CmdShare(os.Args[2:]))
	case "ports":
		os.Exit(sandbox.CmdPorts(os.Args[2:]))
	case "net-policy":
		os.Exit(sandbox.CmdNetworkPolicy(os.Args[2:]))
	case "import":
		os.Exit(sandbox.CmdImport(os.Args[2:]))
	case "stop", "delete":
		if len(os.Args) != 3 {
			fmt.Fprintf(os.Stderr, "usage: gantry %s <name>\n", os.Args[1])
			os.Exit(2)
		}
		name := mustName(os.Args[2])
		if os.Args[1] == "stop" {
			os.Exit(sandbox.CmdStop(name))
		}
		os.Exit(sandbox.CmdDelete(name))
	case "run":
		// fall through below
	default:
		fmt.Fprintf(os.Stderr, "gantry: unknown command %q\n\n", os.Args[1])
		writeMainHelp(os.Stderr)
		os.Exit(2)
	}
	_ = run.Parse(os.Args[2:])
	if *kernel == "" || (*initrd == "" && *rootfs == "") {
		run.Usage()
		os.Exit(2)
	}

	var netMAC [6]byte
	if *netEndpoint != "" {
		hw, err := net.ParseMAC(*netMACArg)
		if err != nil || len(hw) != len(netMAC) {
			fmt.Fprintf(os.Stderr, "gantry: invalid -net-mac %q\n", *netMACArg)
			os.Exit(2)
		}
		copy(netMAC[:], hw)
	}
	var hostShares []vmm.Share
	seenTags := map[string]bool{}
	for _, spec := range shares {
		share, err := vmm.ParseShareSpec(spec, seenTags)
		if err != nil {
			fmt.Fprintf(os.Stderr, "gantry: invalid -share %q: %v\n", spec, err)
			os.Exit(2)
		}
		seenTags[share.Tag] = true
		hostShares = append(hostShares, share)
	}

	cmdline := *append_
	if cmdline == "" {
		arch, err := vmm.KernelArch(*kernel)
		if err != nil {
			fmt.Fprintf(os.Stderr, "gantry run: %v\n", err)
			os.Exit(1)
		}
		cmdline = vmm.DefaultCmdline(arch, *rootfs, *initrd, *guestCID, *netEndpoint, netMAC, *netDHCP)
	}

	var listenPorts []uint32
	if *vsockFwd != "" && *vsockListen != "" {
		for _, s := range strings.Split(*vsockListen, ",") {
			var p uint64
			if _, err := fmt.Sscanf(s, "%d", &p); err == nil && p > 0 {
				listenPorts = append(listenPorts, uint32(p))
			}
		}
	}

	m, err := vmm.Prepare(vmm.Opts{
		MemSize:     uint64(*memMB) << 20,
		KernelPath:  *kernel,
		InitrdPath:  *initrd,
		RootfsPath:  *rootfs,
		Disks:       disks,
		Shares:      hostShares,
		NetEndpoint: *netEndpoint,
		NetMAC:      netMAC,
		NetVFKIT:    *netVFKIT,
		VsockFwd:    *vsockFwd,
		Interactive: true,
		VCPUs:       min(*vcpus, 8),
		GuestCID:    *guestCID,
		VsockListen: listenPorts,
		Cmdline:     cmdline,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "gantry:", err)
		os.Exit(1)
	}

	if *vsockFwd != "" {
		if err := vmm.WriteShareManifest(filepath.Join(*vsockFwd, "shares.json"), hostShares); err != nil {
			fmt.Fprintf(os.Stderr, "gantry: write share manifest: %v\n", err)
		}
	}

	setRawMode()
	err = vmm.Run(m)
	restoreMode() // explicit: os.Exit skips deferred calls
	if err != nil {
		fmt.Fprintln(os.Stderr, "\ngantry:", err)
		os.Exit(1)
	}
}
