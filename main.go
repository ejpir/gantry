package main

import (
	"flag"
	"fmt"
	"gantry/internal/gutil"
	"gantry/internal/sandbox"
	"gantry/internal/vmm"
	"net"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	run := flag.NewFlagSet("run", flag.ExitOnError)
	kernel := run.String("kernel", "", "path to arm64 Linux kernel Image (required)")
	initrd := run.String("initrd", "", "path to initramfs cpio.gz")
	rootfs := run.String("rootfs", "", "path to rootfs image attached as virtio-blk /dev/vda (e.g. nerdbox EROFS)")
	var disks gutil.StrList
	run.Var(&disks, "disk", "extra virtio-blk image (repeatable): /dev/vdb, /dev/vdc, ...")
	var shares gutil.StrList
	run.Var(&shares, "share", "host directory exported through virtio-fs as TAG=PATH[,ro] (repeatable)")
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
		fmt.Fprintf(os.Stderr, `gantry — a tiny microVM monitor (KVM on Linux arm64/x86-64, HVF on macOS).

usage:
  gantry run -kernel Image -initrd initramfs.cpio.gz   # our guest init
  gantry run -kernel Image -rootfs nerdbox-rootfs \    # the real nerdbox
             -vsockfwd /tmp/gantry-vsock               #   guest + vminitd
  gantry exec [flags] [-- CMD]      # one-shot: boot VM + shell in one command
  gantry start <name> [flags]       # create a long-lived sandbox VM
  gantry exec <name> [-- CMD]       # attach a shell to a running sandbox
  gantry ls                         # list sandboxes
  gantry stop <name>                # stop a sandbox
  gantry delete <name>              # stop + remove a sandbox
`)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "exec":
		if len(os.Args) > 2 && !strings.HasPrefix(os.Args[2], "-") {
			os.Exit(sandbox.CmdSandboxExec(sandbox.CheckedSandboxName(os.Args[2]), os.Args[3:]))
		}
		cmdExec(os.Args[2:])
		return
	case "start":
		os.Exit(sandbox.CmdStart(os.Args[2:]))
	case "daemon":
		if len(os.Args) != 3 {
			os.Exit(2)
		}
		os.Exit(sandbox.CmdDaemon(sandbox.CheckedSandboxName(os.Args[2])))
	case "ls":
		os.Exit(sandbox.CmdLs())
	case "stop", "delete":
		if len(os.Args) != 3 {
			fmt.Fprintf(os.Stderr, "usage: gantry %s <name>\n", os.Args[1])
			os.Exit(2)
		}
		name := sandbox.CheckedSandboxName(os.Args[2])
		if os.Args[1] == "stop" {
			os.Exit(sandbox.CmdStop(name))
		}
		os.Exit(sandbox.CmdDelete(name))
	case "run":
		// fall through below
	default:
		os.Exit(2)
	}
	run.Parse(os.Args[2:])
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
