package main

import (
	"flag"
	"fmt"
	"gantry/internal/gutil"
	"gantry/internal/netpol"
	"gantry/internal/sandbox"
	"gantry/internal/vmm"
	"gantry/internal/vnet"
	"net"
	"os"
	"path/filepath"
	"strings"

	"gantry/internal/client"
)

// cmdExec is the sbx-style single-command flow: boot a VM (with gvproxy
// networking, like run-macos.sh container) and immediately start an
// interactive container session — one terminal, one process:
//
//	gantry exec                      # full Debian, writable root, bash
//	gantry exec -- /bin/sh           # pick the command
//	gantry exec -image shell-rootfs.erofs -- /bin/sh
//	gantry exec -share code=$HOME/repos,ro
//	gantry exec -net=false -console  # no gvproxy; watch the guest boot
//
// hostctl + run-macos.sh remain for the two-terminal debug flow.
func cmdExec(argv []string) { os.Exit(runExec(argv)) }

func runExec(argv []string) int {
	fs := flag.NewFlagSet("exec", flag.ExitOnError)
	kernel := fs.String("kernel", vmm.DefaultKernelImage(), "Linux kernel image (arm64 Image or x86-64 vmlinux ELF)")
	rootfs := fs.String("rootfs", vmm.DefaultRootfs(), "VM rootfs (nerdbox EROFS with vminitd)")
	image := fs.String("image", "", "container rootfs disk, /dev/vdb (default: debian-bookworm.erofs if present, else shell-rootfs.erofs)")
	rwlayer := fs.String("rwlayer", "", "ext4 writable layer, /dev/vdc (default: rwlayer.ext4 if present)")
	rwFlag := fs.Bool("rw", false, "writable overlay container root (default: on when a rwlayer is available)")
	var shares gutil.StrList
	fs.Var(&shares, "share", "host directory exported through virtio-fs as TAG=PATH[,ro] (repeatable)")
	netEnabled := fs.Bool("net", true, "attach virtio-net via the embedded netstack")
	gvproxy := fs.String("gvproxy", "", "use this external gvproxy binary instead of the embedded netstack")
	netpolFlag := fs.String("net-policy", "", "JSON egress policy file (rules + domain allowlist)")
	console := fs.Bool("console", false, "stream the guest serial console to stderr (default: log file in the work dir)")
	memMB := fs.Uint("mem", 512, "guest RAM in MiB")
	vcpus := fs.Int("cpus", 1, "guest vCPU count (max 8)")

	args := []string(nil)
	for i, a := range argv {
		if a == "--" {
			args = argv[i+1:]
			argv = argv[:i]
			break
		}
	}
	fs.Parse(argv)

	// --- resolve defaults -------------------------------------------------
	img := *image
	if img == "" {
		if gutil.FileExists("debian-bookworm.erofs") {
			img = "debian-bookworm.erofs"
		} else {
			img = "shell-rootfs.erofs"
		}
	}
	rwl := *rwlayer
	if rwl == "" && gutil.FileExists("rwlayer.ext4") {
		rwl = "rwlayer.ext4"
	}
	rwSet := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "rw" {
			rwSet = true
		}
	})
	rw := *rwFlag
	if !rwSet && rwl != "" {
		rw = true // a writable layer exists: default to the full-OS experience
	}
	if rwl == "" {
		rw = false
	}
	if len(args) == 0 {
		if strings.Contains(strings.ToLower(filepath.Base(img)), "debian") {
			args = []string{"/bin/bash"}
		} else {
			args = []string{"/bin/sh"}
		}
	}

	var hostShares []vmm.Share
	seenTags := map[string]bool{}
	for _, spec := range shares {
		share, err := vmm.ParseShareSpec(spec, seenTags)
		if err != nil {
			fmt.Fprintf(os.Stderr, "gantry exec: invalid -share %q: %v\n", spec, err)
			return 2
		}
		seenTags[share.Tag] = true
		hostShares = append(hostShares, share)
	}

	for _, req := range []string{*kernel, *rootfs, img} {
		if !gutil.FileExists(req) {
			fmt.Fprintf(os.Stderr, "gantry exec: missing %s\n", req)
			return 1
		}
	}
	if rw && !gutil.FileExists(rwl) {
		fmt.Fprintf(os.Stderr, "gantry exec: missing %s\n", rwl)
		return 1
	}

	// --- work dir (vsock sockets, shares.json, console log) ---------------
	tmp, err := os.MkdirTemp("", "gantry-exec-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "gantry exec:", err)
		return 1
	}
	keepTmp := false // startup failures keep the dir so logs survive
	defer func() {
		if !keepTmp {
			os.RemoveAll(tmp)
		}
	}()
	fmt.Printf("gantry exec: work dir %s\n", tmp)
	dumpLog := func(name string) {
		b, err := os.ReadFile(filepath.Join(tmp, name))
		if err != nil || len(b) == 0 {
			return
		}
		if len(b) > 4096 {
			b = b[len(b)-4096:]
		}
		fmt.Fprintf(os.Stderr, "---- last bytes of %s ----\n%s\n----\n", name, b)
	}

	// --- guest console: log file by default, stderr with -console ---------
	if *console {
		vmm.SetConsoleWriter(os.Stderr)
	} else {
		logf, err := os.Create(filepath.Join(tmp, "console.log"))
		if err != nil {
			fmt.Fprintln(os.Stderr, "gantry exec:", err)
			return 1
		}
		defer logf.Close()
		vmm.SetConsoleWriter(logf)
		fmt.Printf("gantry exec: guest console → %s (use -console to watch it live)\n", logf.Name())
	}

	// --- networking (embedded netstack; external gvproxy is an override) ---
	netMAC := [6]byte{0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee}
	netSock := ""
	var netConn net.Conn
	var policy *netpol.Policy
	if *netpolFlag != "" {
		if *gvproxy != "" {
			fmt.Fprintln(os.Stderr, "gantry exec: -net-policy requires the embedded netstack (drop -gvproxy)")
			return 1
		}
		var err error
		policy, err = netpol.Load(*netpolFlag)
		if err != nil {
			fmt.Fprintln(os.Stderr, "gantry exec:", err)
			return 1
		}
		fmt.Println("gantry exec: network policy:", policy.Describe())
	}
	if *netEnabled {
		if *gvproxy != "" {
			gv, sock, err := sandbox.StartGVProxy(*gvproxy, tmp)
			if err != nil {
				keepTmp = true
				fmt.Fprintf(os.Stderr, "gantry exec: %v (use -net=false to skip)\n", err)
				dumpLog("gvproxy.log")
				return 1
			}
			defer func() { gv.Process.Kill(); gv.Wait() }()
			netSock = sock
			fmt.Println("gantry exec: gvproxy network ready")
		} else {
			stack, err := vnet.Start(netMAC)
			if err != nil {
				fmt.Fprintln(os.Stderr, "gantry exec:", err)
				return 1
			}
			defer stack.Close()
			netConn, err = stack.Dial()
			if err != nil {
				fmt.Fprintln(os.Stderr, "gantry exec:", err)
				return 1
			}
			defer netConn.Close()
			fmt.Println("gantry exec: embedded netstack ready")
		}
	}

	// --- machine ------------------------------------------------------------
	disks := []string{img}
	if rw {
		disks = append(disks, rwl)
	}
	arch, err := vmm.KernelArch(*kernel)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gantry exec:", err)
		return 1
	}
	m, err := vmm.Prepare(vmm.Opts{
		MemSize:     uint64(*memMB) << 20,
		KernelPath:  *kernel,
		RootfsPath:  *rootfs,
		Disks:       disks,
		Shares:      hostShares,
		NetEndpoint: netSock,
		NetConn:     netConn,
		NetPolicy:   policy,
		NetMAC:      netMAC,
		NetVFKIT:    true,
		VsockFwd:    tmp,
		VCPUs:       min(*vcpus, 8),
		GuestCID:    3,
		VsockListen: []uint32{1026},
		Cmdline:     vmm.DefaultCmdline(arch, *rootfs, "", 3, netMarkerExec(netSock, netConn), netMAC, true),
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "gantry exec:", err)
		return 1
	}
	if err := vmm.WriteShareManifest(filepath.Join(tmp, "shares.json"), hostShares); err != nil {
		fmt.Fprintf(os.Stderr, "gantry exec: write share manifest: %v\n", err)
	}

	guestErr := make(chan error, 1)
	go func() { guestErr <- vmm.Run(m) }()

	// --- session ------------------------------------------------------------
	shellErr := make(chan error, 1)
	go func() {
		shellErr <- client.Shell(client.ShellOptions{
			RPCSock:    filepath.Join(tmp, "1025.sock"),
			StreamSock: filepath.Join(tmp, "listen-1026.sock"),
			Share:      len(hostShares) > 0,
			RW:         rw,
			Args:       args,
		})
	}()

	select {
	case err := <-shellErr:
		fmt.Println("gantry exec: shutting down the VM")
		if err != nil {
			fmt.Fprintf(os.Stderr, "gantry exec: %v\n", err)
			return 1
		}
	case gerr := <-guestErr:
		keepTmp = true
		fmt.Fprintf(os.Stderr, "gantry exec: VM exited before the session started: %v\n", gerr)
		dumpLog("console.log")
		dumpLog("gvproxy.log")
		return 1
	}
	return 0
}

func netMarkerExec(endpoint string, conn net.Conn) string {
	if endpoint != "" || conn != nil {
		return "enabled"
	}
	return ""
}
