package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

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
	kernel := fs.String("kernel", defaultKernelImage(), "Linux kernel image (arm64 Image or x86-64 vmlinux ELF)")
	rootfs := fs.String("rootfs", defaultRootfs(), "VM rootfs (nerdbox EROFS with vminitd)")
	image := fs.String("image", "", "container rootfs disk, /dev/vdb (default: debian-bookworm.erofs if present, else shell-rootfs.erofs)")
	rwlayer := fs.String("rwlayer", "", "ext4 writable layer, /dev/vdc (default: rwlayer.ext4 if present)")
	rwFlag := fs.Bool("rw", false, "writable overlay container root (default: on when a rwlayer is available)")
	var shares strList
	fs.Var(&shares, "share", "host directory exported through virtio-fs as TAG=PATH[,ro] (repeatable)")
	netEnabled := fs.Bool("net", true, "start gvproxy and attach virtio-net")
	gvproxy := fs.String("gvproxy", defaultGvproxy(), "path to the gvproxy binary (with -net)")
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
		if fileExists("debian-bookworm.erofs") {
			img = "debian-bookworm.erofs"
		} else {
			img = "shell-rootfs.erofs"
		}
	}
	rwl := *rwlayer
	if rwl == "" && fileExists("rwlayer.ext4") {
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

	var hostShares []hostShare
	seenTags := map[string]bool{}
	for _, spec := range shares {
		share, err := parseShareSpec(spec, seenTags)
		if err != nil {
			fmt.Fprintf(os.Stderr, "gantry exec: invalid -share %q: %v\n", spec, err)
			return 2
		}
		seenTags[share.tag] = true
		hostShares = append(hostShares, share)
	}

	for _, req := range []string{*kernel, *rootfs, img} {
		if !fileExists(req) {
			fmt.Fprintf(os.Stderr, "gantry exec: missing %s\n", req)
			return 1
		}
	}
	if rw && !fileExists(rwl) {
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
		consoleWriter = os.Stderr
	} else {
		logf, err := os.Create(filepath.Join(tmp, "console.log"))
		if err != nil {
			fmt.Fprintln(os.Stderr, "gantry exec:", err)
			return 1
		}
		defer logf.Close()
		consoleWriter = logf
		fmt.Printf("gantry exec: guest console → %s (use -console to watch it live)\n", logf.Name())
	}

	// --- gvproxy ----------------------------------------------------------
	netSock := ""
	if *netEnabled {
		gv, sock, err := startGVProxy(*gvproxy, tmp)
		if err != nil {
			keepTmp = true
			fmt.Fprintf(os.Stderr, "gantry exec: %v (use -net=false to skip)\n", err)
			dumpLog("gvproxy.log")
			return 1
		}
		defer func() { gv.Process.Kill(); gv.Wait() }()
		netSock = sock
		fmt.Println("gantry exec: gvproxy network ready")
	}

	// --- machine ------------------------------------------------------------
	netMAC := [6]byte{0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee}
	disks := []string{img}
	if rw {
		disks = append(disks, rwl)
	}
	arch, err := kernelArch(*kernel)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gantry exec:", err)
		return 1
	}
	m, err := prepareMachine(machineOpts{
		memSize:     uint64(*memMB) << 20,
		kernelPath:  *kernel,
		rootfsPath:  *rootfs,
		disks:       disks,
		shares:      hostShares,
		netEndpoint: netSock,
		netMAC:      netMAC,
		netVFKIT:    true,
		vsockFwd:    tmp,
		vcpus:       min(*vcpus, 8),
		guestCID:    3,
		vsockListen: []uint32{1026},
		cmdline:     defaultCmdline(arch, *rootfs, "", 3, netSock, netMAC, true),
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "gantry exec:", err)
		return 1
	}
	if err := writeShareManifest(filepath.Join(tmp, "shares.json"), hostShares); err != nil {
		fmt.Fprintf(os.Stderr, "gantry exec: write share manifest: %v\n", err)
	}

	guestErr := make(chan error, 1)
	go func() { guestErr <- runGuest(m) }()

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

func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}

// freeTCPPort returns a currently-unused localhost TCP port.
func freeTCPPort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// startGVProxy launches gvproxy with its API and vfkit unixgram sockets in
// dir and waits for the vfkit socket. The caller kills the process.
func startGVProxy(binPath, dir string) (*exec.Cmd, string, error) {
	netSock := filepath.Join(dir, "net.sock")
	apiSock := filepath.Join(dir, "gvproxy-api.sock")
	netLog, err := os.Create(filepath.Join(dir, "gvproxy.log"))
	if err != nil {
		return nil, "", err
	}
	gvPath := binPath
	if !strings.ContainsRune(gvPath, os.PathSeparator) && fileExists(gvPath) {
		// exec.Command only searches $PATH for bare names; prefer the
		// binary next to gantry (what run-macos.sh does with ./gvproxy).
		if abs, err := filepath.Abs(gvPath); err == nil {
			gvPath = abs
		}
	}
	// gvproxy's SSH-forward listener defaults to tcp/2222, so every second
	// instance (stale process or a concurrent sandbox) dies with "address
	// already in use". gvproxy rejects -ssh-port 0 ("must be between 1024
	// and 65535"), so grab a free port ourselves; we never use the SSH
	// forward anyway.
	sshPort, err := freeTCPPort()
	if err != nil {
		netLog.Close()
		return nil, "", fmt.Errorf("allocate gvproxy ssh port: %w", err)
	}
	cmd := exec.Command(gvPath, "-debug", "-ssh-port", fmt.Sprint(sshPort), "-listen", "unix://"+apiSock, "-listen-vfkit", "unixgram://"+netSock)
	cmd.Stdout, cmd.Stderr = netLog, netLog
	if err := cmd.Start(); err != nil {
		netLog.Close()
		return nil, "", fmt.Errorf("start gvproxy: %w", err)
	}
	// Record the pid so `gantry stop` can clean up even if the daemon was
	// SIGKILLed (defers don't run then, orphaning gvproxy on port 2222...).
	os.WriteFile(filepath.Join(dir, "gvproxy.pid"), []byte(fmt.Sprint(cmd.Process.Pid)), 0o644)
	for i := 0; i < 300 && !fileExists(netSock); i++ {
		time.Sleep(50 * time.Millisecond)
	}
	if !fileExists(netSock) {
		netLog.Close()
		cmd.Process.Kill()
		cmd.Wait()
		return nil, "", fmt.Errorf("gvproxy did not create %s", netSock)
	}
	return cmd, netSock, nil
}
