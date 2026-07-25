package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func main() {
	run := flag.NewFlagSet("run", flag.ExitOnError)
	kernel := run.String("kernel", "", "path to arm64 Linux kernel Image (required)")
	initrd := run.String("initrd", "", "path to initramfs cpio.gz")
	rootfs := run.String("rootfs", "", "path to rootfs image attached as virtio-blk /dev/vda (e.g. nerdbox EROFS)")
	var disks strList
	run.Var(&disks, "disk", "extra virtio-blk image (repeatable): /dev/vdb, /dev/vdc, ...")
	var shares strList
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
			os.Exit(cmdSandboxExec(checkedSandboxName(os.Args[2]), os.Args[3:]))
		}
		cmdExec(os.Args[2:])
		return
	case "start":
		os.Exit(cmdStart(os.Args[2:]))
	case "daemon":
		if len(os.Args) != 3 {
			os.Exit(2)
		}
		os.Exit(cmdDaemon(checkedSandboxName(os.Args[2])))
	case "ls":
		os.Exit(cmdLs())
	case "stop", "delete":
		if len(os.Args) != 3 {
			fmt.Fprintf(os.Stderr, "usage: gantry %s <name>\n", os.Args[1])
			os.Exit(2)
		}
		name := checkedSandboxName(os.Args[2])
		if os.Args[1] == "stop" {
			os.Exit(cmdStop(name))
		}
		os.Exit(cmdDelete(name))
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
	var hostShares []hostShare
	seenTags := map[string]bool{}
	for _, spec := range shares {
		share, err := parseShareSpec(spec, seenTags)
		if err != nil {
			fmt.Fprintf(os.Stderr, "gantry: invalid -share %q: %v\n", spec, err)
			os.Exit(2)
		}
		seenTags[share.tag] = true
		hostShares = append(hostShares, share)
	}

	cmdline := *append_
	if cmdline == "" {
		arch, err := kernelArch(*kernel)
		if err != nil {
			fmt.Fprintf(os.Stderr, "gantry run: %v\n", err)
			os.Exit(1)
		}
		cmdline = defaultCmdline(arch, *rootfs, *initrd, *guestCID, *netEndpoint, netMAC, *netDHCP)
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

	m, err := prepareMachine(machineOpts{
		memSize:     uint64(*memMB) << 20,
		kernelPath:  *kernel,
		initrdPath:  *initrd,
		rootfsPath:  *rootfs,
		disks:       disks,
		shares:      hostShares,
		netEndpoint: *netEndpoint,
		netMAC:      netMAC,
		netVFKIT:    *netVFKIT,
		vsockFwd:    *vsockFwd,
		interactive: true,
		vcpus:       min(*vcpus, 8),
		guestCID:    *guestCID,
		vsockListen: listenPorts,
		cmdline:     cmdline,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "gantry:", err)
		os.Exit(1)
	}

	if *vsockFwd != "" {
		if err := writeShareManifest(filepath.Join(*vsockFwd, "shares.json"), hostShares); err != nil {
			fmt.Fprintf(os.Stderr, "gantry: write share manifest: %v\n", err)
		}
	}

	setRawMode()
	err = runGuest(m)
	restoreMode() // explicit: os.Exit skips deferred calls
	if err != nil {
		fmt.Fprintln(os.Stderr, "\ngantry:", err)
		os.Exit(1)
	}
}

// defaultKernelImage/defaultRootfs pick the nerdbox assets matching the
// host architecture (sbx ships nerdbox-{kernel,rootfs}-{arm64,x86_64}).
func defaultKernelImage() string {
	if runtime.GOARCH == "amd64" {
		return "nerdbox-kernel-x86_64"
	}
	return "nerdbox-kernel-arm64"
}

func defaultRootfs() string {
	if runtime.GOARCH == "amd64" {
		return "nerdbox-rootfs-x86_64.erofs"
	}
	return "nerdbox-rootfs-arm64.erofs"
}

// defaultGvproxy names the gvproxy binary for this platform (upstream
// gvisor-tap-vsock releases: gvproxy-{linux,darwin,windows}-{arch}).
func defaultGvproxy() string {
	s := "gvproxy-" + runtime.GOOS + "-" + runtime.GOARCH
	if runtime.GOOS == "windows" {
		s += ".exe"
	}
	return s
}

// defaultCmdline mirrors nerdbox's libkrun instance.go (PL011 on arm64,
// 16550 on x86 replaces virtio-console). Arguments after "--" configure
// vminitd.
func defaultCmdline(arch, rootfsPath, initrdPath string, guestCID uint64, netEndpoint string, netMAC [6]byte, netDHCP bool) string {
	console := "console=ttyAMA0"
	if arch == "amd64" {
		console = "console=ttyS0"
	}
	switch {
	case rootfsPath != "" && initrdPath != "":
		// combo: kernel runs our init from the initramfs; it mounts the
		// attached rootfs at /mnt (no root= on purpose)
		return console + " panic=-1 nokaslr"
	case rootfsPath != "":
		cmdline := fmt.Sprintf("%s root=/dev/vda rootfstype=erofs ro nokaslr init=/sbin/vminitd -- -vsock-rpc-port=1025 -vsock-stream-port=1026 -vsock-cid=%d", console, guestCID)
		if netEndpoint != "" {
			cmdline += fmt.Sprintf(" -network=mac=%s", net.HardwareAddr(netMAC[:]))
			if netDHCP {
				cmdline += ",dhcp=true"
			}
		}
		return cmdline
	default:
		return console + " panic=-1 nokaslr"
	}
}

// strList is a repeatable string flag.
type strList []string

func (s *strList) String() string { return fmt.Sprint([]string(*s)) }
func (s *strList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func validShareTag(tag string) bool {
	if tag == "" || len([]byte(tag)) > virtioFSTagLen {
		return false
	}
	for _, r := range tag {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}
