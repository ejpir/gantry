package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"gantry/internal/client"

	"github.com/containerd/ttrpc"
	"golang.org/x/term"
)

// Sandbox lifecycle, mirroring `sbx create/start/stop/ls/delete` +
// `sbx exec`. A sandbox is a long-lived VMM daemon holding the single
// vsock dial-back ttrpc connection vminitd makes per VM lifetime
// (dialBackListener dials exactly once). `gantry exec <name>` is a thin
// client; the daemon multiplexes sessions over that one connection (ttrpc
// streams are independent, so concurrent exec sessions are fine).
//
// State per sandbox under ~/.gantry/sandboxes/<name>/:
//
//	sandbox.json      start configuration (images, rw, shares, net)
//	vmm.pid           daemon process id
//	ready             touched once the guest RPC connection is held
//	ctl.sock          session broker (JSON line, then raw stdio)
//	1025.sock         vsock dial-back accept target
//	listen-1026.sock  vsock stream listener
//	console.log       guest serial console
//	gvproxy.log       network backend log
//	daemon.log        daemon stdout/stderr

type sandboxConfig struct {
	Kernel  string   `json:"kernel"`
	Rootfs  string   `json:"rootfs"`
	Image   string   `json:"image"`
	RWLayer string   `json:"rwlayer,omitempty"`
	RW      bool     `json:"rw"`
	Shares  []string `json:"shares,omitempty"` // raw TAG=PATH[,ro] specs
	Net     bool     `json:"net"`
	GVProxy string   `json:"gvproxy,omitempty"`
	MemMB   uint     `json:"memMB"`
	VCPUs   int      `json:"vcpus,omitempty"`
}

func sandboxRoot() string {
	if d := envOr("GANTRY_HOME", "MINIVM_HOME"); d != "" {
		return d
	}
	home, err := os.UserHomeDir()
	if err != nil {
		home = "/tmp"
	}
	newRoot := filepath.Join(home, ".gantry", "sandboxes")
	oldRoot := filepath.Join(home, ".minivm", "sandboxes")
	// one-time migration after the project rename
	if _, err := os.Stat(newRoot); os.IsNotExist(err) {
		if _, err := os.Stat(oldRoot); err == nil {
			os.MkdirAll(filepath.Dir(newRoot), 0o755)
			if err := os.Rename(oldRoot, newRoot); err == nil {
				fmt.Println("gantry: migrated sandboxes ~/.gantry -> ~/.gantry")
			}
		}
	}
	return newRoot
}

func sandboxDir(name string) string { return filepath.Join(sandboxRoot(), name) }

func validSandboxName(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}

func sandboxPID(name string) (int, bool) {
	b, err := os.ReadFile(filepath.Join(sandboxDir(name), "vmm.pid"))
	if err != nil {
		return 0, false
	}
	var pid int
	fmt.Sscanf(string(b), "%d", &pid)
	if pid <= 0 {
		return 0, false
	}
	if !procAlive(pid) {
		return pid, false // stale pid file
	}
	return pid, true
}

// ---------------- gantry start <name> [flags] ------------------------------

func cmdStart(argv []string) int {
	if len(argv) == 0 || strings.HasPrefix(argv[0], "-") || !validSandboxName(argv[0]) {
		fmt.Fprintln(os.Stderr, "usage: gantry start <name> [flags]  (name: letters, digits, ._-)")
		return 2
	}
	name, fargv := argv[0], argv[1:]

	fs := flag.NewFlagSet("start", flag.ExitOnError)
	kernel := fs.String("kernel", defaultKernelImage(), "")
	rootfs := fs.String("rootfs", defaultRootfs(), "")
	image := fs.String("image", "", "container rootfs (default: debian-bookworm.erofs if present, else shell-rootfs.erofs)")
	rwlayer := fs.String("rwlayer", "", "ext4 writable layer (default: rwlayer.ext4 if present)")
	rw := fs.Bool("rw", false, "writable overlay container root (default: on when a rwlayer exists)")
	var shares strList
	fs.Var(&shares, "share", "TAG=PATH[,ro] (repeatable)")
	netEnabled := fs.Bool("net", true, "")
	gvproxy := fs.String("gvproxy", defaultGvproxy(), "")
	memMB := fs.Uint("mem", 512, "")
	vcpus := fs.Int("cpus", 1, "guest vCPU count (max 8)")
	fs.Parse(fargv)

	if _, alive := sandboxPID(name); alive {
		fmt.Fprintf(os.Stderr, "gantry start: sandbox %q is already running\n", name)
		return 1
	}

	// The daemon runs with cwd=/, so resolve everything to absolute paths.
	gvPath := *gvproxy
	if !strings.ContainsRune(gvPath, os.PathSeparator) && fileExists(gvPath) {
		gvPath = absPath(gvPath)
	}
	cfg := sandboxConfig{
		Kernel:  absPath(*kernel),
		Rootfs:  absPath(*rootfs),
		Image:   *image,
		RWLayer: *rwlayer,
		Shares:  shares,
		Net:     *netEnabled,
		GVProxy: gvPath,
		MemMB:   *memMB,
		VCPUs:   min(*vcpus, 8),
	}
	if cfg.Image == "" {
		if fileExists("debian-bookworm.erofs") {
			cfg.Image = "debian-bookworm.erofs"
		} else {
			cfg.Image = "shell-rootfs.erofs"
		}
	}
	cfg.Image = absPath(cfg.Image)
	if cfg.RWLayer == "" && fileExists("rwlayer.ext4") {
		cfg.RWLayer = "rwlayer.ext4"
	}
	if cfg.RWLayer != "" {
		cfg.RWLayer = absPath(cfg.RWLayer)
	}
	rwSet := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "rw" {
			rwSet = true
		}
	})
	cfg.RW = *rw || (!rwSet && cfg.RWLayer != "")
	if !rwSet && cfg.RWLayer == "" {
		cfg.RW = false
	}
	for _, req := range []string{cfg.Kernel, cfg.Rootfs, cfg.Image} {
		if !fileExists(req) {
			fmt.Fprintf(os.Stderr, "gantry start: missing %s\n", req)
			return 1
		}
	}
	if cfg.RW && cfg.RWLayer != "" && !fileExists(cfg.RWLayer) {
		fmt.Fprintf(os.Stderr, "gantry start: rwlayer %s does not exist; create it with:\n  ./mkrwlayer.sh %s 512\n", cfg.RWLayer, cfg.RWLayer)
		return 1
	}
	// Validate share specs now, with absolute paths for the daemon.
	seen := map[string]bool{}
	for i, spec := range cfg.Shares {
		s, err := parseShareSpec(spec, seen)
		if err != nil {
			fmt.Fprintf(os.Stderr, "gantry start: invalid -share %q: %v\n", spec, err)
			return 2
		}
		seen[s.tag] = true
		p, err := filepath.Abs(s.path)
		if err == nil {
			cfg.Shares[i] = s.tag + "=" + p
			if s.ro {
				cfg.Shares[i] += ",ro"
			}
		}
	}

	dir := sandboxDir(name)
	os.RemoveAll(dir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "gantry start:", err)
		return 1
	}
	b, _ := json.MarshalIndent(cfg, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "sandbox.json"), b, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "gantry start:", err)
		return 1
	}

	// Detached daemon: same binary, signed (this is why start goes through
	// run-macos.sh on macOS: build+codesign first).
	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "gantry start:", err)
		return 1
	}
	logf, err := os.Create(filepath.Join(dir, "daemon.log"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "gantry start:", err)
		return 1
	}
	defer logf.Close()
	cmd := exec.Command(exe, "daemon", name)
	cmd.Dir = "/"
	cmd.Stdout, cmd.Stderr = logf, logf
	detachDaemon(cmd)
	if err := cmd.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "gantry start: spawn daemon:", err)
		return 1
	}
	os.WriteFile(filepath.Join(dir, "vmm.pid"), []byte(fmt.Sprint(cmd.Process.Pid)), 0o644)
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()

	fmt.Printf("gantry start: sandbox %q booting (vmm pid %d)\n", name, cmd.Process.Pid)
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if fileExists(filepath.Join(dir, "ready")) {
			fmt.Printf("gantry start: sandbox %q is up — attach with: gantry exec %s\n", name, name)
			return 0
		}
		select {
		case err := <-exited:
			fmt.Fprintf(os.Stderr, "gantry start: daemon exited during boot: %v\n", err)
			dumpTail(filepath.Join(dir, "console.log"))
			dumpTail(filepath.Join(dir, "daemon.log"))
			return 1
		default:
		}
		time.Sleep(100 * time.Millisecond)
	}
	fmt.Fprintf(os.Stderr, "gantry start: timed out waiting for the guest RPC connection; see %s\n", dir)
	return 1
}

// ---------------- gantry daemon <name> (hidden, foreground) -----------------

func cmdDaemon(name string) int {
	dir := sandboxDir(name)
	b, err := os.ReadFile(filepath.Join(dir, "sandbox.json"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "daemon:", err)
		return 1
	}
	var cfg sandboxConfig
	if json.Unmarshal(b, &cfg) != nil {
		fmt.Fprintln(os.Stderr, "daemon: corrupt sandbox.json")
		return 1
	}

	console, err := os.Create(filepath.Join(dir, "console.log"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "daemon:", err)
		return 1
	}
	defer console.Close()
	consoleWriter = console

	netSock := ""
	if cfg.Net {
		gv, sock, err := startGVProxy(cfg.GVProxy, dir)
		if err != nil {
			fmt.Fprintln(os.Stderr, "daemon:", err)
			return 1
		}
		defer func() { gv.Process.Kill(); gv.Wait() }()
		netSock = sock
	}

	var hostShares []hostShare
	seen := map[string]bool{}
	for _, spec := range cfg.Shares {
		s, err := parseShareSpec(spec, seen)
		if err != nil {
			fmt.Fprintln(os.Stderr, "daemon: bad share:", err)
			return 1
		}
		seen[s.tag] = true
		hostShares = append(hostShares, s)
	}

	netMAC := [6]byte{0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee}
	disks := []string{cfg.Image}
	if cfg.RW && cfg.RWLayer != "" {
		disks = append(disks, cfg.RWLayer)
	}
	arch, err := kernelArch(cfg.Kernel)
	if err != nil {
		fmt.Fprintln(os.Stderr, "daemon:", err)
		return 1
	}
	m, err := prepareMachine(machineOpts{
		memSize:     uint64(cfg.MemMB) << 20,
		kernelPath:  cfg.Kernel,
		rootfsPath:  cfg.Rootfs,
		disks:       disks,
		shares:      hostShares,
		netEndpoint: netSock,
		netMAC:      netMAC,
		netVFKIT:    true,
		vsockFwd:    dir,
		vcpus:       cfg.VCPUs,
		guestCID:    3,
		vsockListen: []uint32{1026},
		cmdline:     insertExtraCmdline(defaultCmdline(arch, cfg.Rootfs, "", 3, netSock, netMAC, true)),
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "daemon:", err)
		return 1
	}
	if err := writeShareManifest(filepath.Join(dir, "shares.json"), hostShares); err != nil {
		fmt.Fprintln(os.Stderr, "daemon: share manifest:", err)
	}

	guestErr := make(chan error, 1)
	go func() { guestErr <- runGuest(m) }()

	// Hold the single dial-back connection for the VM's lifetime.
	rpc, err := client.AcceptRPC(filepath.Join(dir, "1025.sock"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "daemon:", err)
		return 1
	}
	defer rpc.Close()
	os.WriteFile(filepath.Join(dir, "ready"), []byte("1\n"), 0o644)
	fmt.Println("daemon: guest RPC connection held; broker on ctl.sock")

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)

	ln, err := net.Listen("unix", filepath.Join(dir, "ctl.sock"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "daemon:", err)
		return 1
	}
	defer ln.Close()

	br := &broker{
		cfg:        cfg,
		dir:        dir,
		rpc:        rpc,
		streamSock: filepath.Join(dir, "listen-1026.sock"),
		sessions:   map[string]chan struct{}{},
	}
	go br.serve(ln)

	select {
	case s := <-sigc:
		fmt.Println("daemon: signal", s, "— shutting down")
		return 0
	case err := <-guestErr:
		fmt.Fprintln(os.Stderr, "daemon: VM exited:", err)
		return 1
	}
}

// broker accepts ctl connections. Protocol: one JSON request line, then
// (for "session") one JSON response line and the socket turns into raw
// bidirectional stdio until the task exits.
type broker struct {
	cfg        sandboxConfig
	dir        string
	rpc        *ttrpc.Client
	streamSock string

	mu       sync.Mutex
	sessions map[string]chan struct{}
}

type brokerRequest struct {
	Op   string   `json:"op"` // "session" | "kill"
	ID   string   `json:"id"`
	Args []string `json:"args,omitempty"`
	Cols uint32   `json:"cols,omitempty"`
	Rows uint32   `json:"rows,omitempty"`
}

func (br *broker) serve(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go br.handle(c)
	}
}

func (br *broker) handle(c net.Conn) {
	defer c.Close()
	line, err := bufio.NewReader(c).ReadBytes('\n')
	if err != nil {
		return
	}
	var req brokerRequest
	if json.Unmarshal(line, &req) != nil || req.ID == "" {
		fmt.Fprintln(c, `{"error":"bad request"}`)
		return
	}
	switch req.Op {
	case "kill":
		br.mu.Lock()
		killCh, ok := br.sessions[req.ID]
		if ok {
			close(killCh)
			delete(br.sessions, req.ID)
		}
		br.mu.Unlock()
		if !ok {
			fmt.Fprintln(c, `{"error":"no such session"}`)
			return
		}
		fmt.Fprintln(c, `{"ok":true}`)
	case "session":
		br.session(c, req)
	default:
		fmt.Fprintln(c, `{"error":"unknown op"}`)
	}
}

func (br *broker) session(c net.Conn, req brokerRequest) {
	killCh := make(chan struct{})
	br.mu.Lock()
	if _, dup := br.sessions[req.ID]; dup {
		br.mu.Unlock()
		fmt.Fprintln(c, `{"error":"duplicate session id"}`)
		return
	}
	br.sessions[req.ID] = killCh
	br.mu.Unlock()
	defer func() {
		br.mu.Lock()
		delete(br.sessions, req.ID)
		br.mu.Unlock()
	}()

	if _, err := fmt.Fprintln(c, `{"ok":true}`); err != nil {
		return
	}
	args := req.Args
	if len(args) == 0 {
		if strings.Contains(strings.ToLower(filepath.Base(br.cfg.Image)), "debian") {
			args = []string{"/bin/bash"}
		} else {
			args = []string{"/bin/sh"}
		}
	}
	err := client.Session(br.rpc, client.SessionOptions{
		StreamSock: br.streamSock,
		Shares:     client.LoadShares(filepath.Join(br.dir, "1025.sock")),
		RW:         br.cfg.RW,
		Args:       args,
		ID:         "sb-" + req.ID,
		Cols:       req.Cols,
		Rows:       req.Rows,
		KillCh:     killCh,
	}, c, c)
	if err != nil {
		fmt.Fprintf(c, "\n[gantry] session error: %v\n", err)
	}
}

// ---------------- gantry exec <name> [-- CMD] -------------------------------

func cmdSandboxExec(name string, argv []string) int {
	dir := sandboxDir(name)
	if _, alive := sandboxPID(name); !alive {
		fmt.Fprintf(os.Stderr, "gantry exec: sandbox %q is not running (start it with: gantry start %s)\n", name, name)
		return 1
	}
	args := argv
	for i, a := range argv {
		if a == "--" {
			args = argv[i+1:]
			break
		}
		if !strings.HasPrefix(a, "-") {
			fmt.Fprintf(os.Stderr, "gantry exec: unexpected argument %q (want: gantry exec %s [-- CMD ...])\n", a, name)
			return 2
		}
		fmt.Fprintf(os.Stderr, "gantry exec: no flags supported in attach mode (want: gantry exec %s [-- CMD ...])\n", name)
		return 2
	}

	c, err := net.Dial("unix", filepath.Join(dir, "ctl.sock"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "gantry exec: broker: %v\n", err)
		return 1
	}
	defer c.Close()

	id := fmt.Sprintf("%d-%d", os.Getpid(), time.Now().UnixNano()%1_000_000)
	req := brokerRequest{Op: "session", ID: id, Args: args}
	if term.IsTerminal(int(os.Stdin.Fd())) {
		if w, h, err := term.GetSize(int(os.Stdout.Fd())); err == nil {
			req.Cols, req.Rows = uint32(w), uint32(h)
		}
	}
	if err := json.NewEncoder(c).Encode(&req); err != nil {
		fmt.Fprintf(os.Stderr, "gantry exec: %v\n", err)
		return 1
	}
	r := bufio.NewReader(c)
	line, err := r.ReadBytes('\n')
	if err != nil {
		fmt.Fprintf(os.Stderr, "gantry exec: broker handshake: %v\n", err)
		return 1
	}
	var resp struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if json.Unmarshal(line, &resp) != nil || !resp.OK {
		fmt.Fprintf(os.Stderr, "gantry exec: broker rejected: %s\n", strings.TrimSpace(string(line)))
		return 1
	}

	if term.IsTerminal(int(os.Stdin.Fd())) {
		if old, err := term.MakeRaw(int(os.Stdin.Fd())); err == nil {
			defer term.Restore(int(os.Stdin.Fd()), old)
		}
	}
	// ctrl-C: ask the broker to kill the task, keep the session attached.
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt)
	defer signal.Stop(sigc)
	go func() {
		<-sigc
		kc, err := net.Dial("unix", filepath.Join(dir, "ctl.sock"))
		if err == nil {
			json.NewEncoder(kc).Encode(&brokerRequest{Op: "kill", ID: id})
			kc.Close()
		}
	}()

	done := make(chan struct{})
	go func() { io.Copy(c, os.Stdin) }()
	go func() {
		io.Copy(os.Stdout, r) // r (not c): the handshake line came through the bufio reader
		close(done)
	}()
	<-done
	return 0
}

// ---------------- gantry ls / stop / delete ---------------------------------

func cmdLs() int {
	ents, err := os.ReadDir(sandboxRoot())
	if err != nil || len(ents) == 0 {
		fmt.Println("no sandboxes (create one with: gantry start <name>)")
		return 0
	}
	fmt.Printf("%-20s %-10s %-8s %s\n", "NAME", "STATE", "PID", "IMAGE")
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		state, pidStr := "stopped", "-"
		if pid, alive := sandboxPID(name); alive {
			state, pidStr = "running", fmt.Sprint(pid)
		}
		image := "-"
		if b, err := os.ReadFile(filepath.Join(sandboxDir(name), "sandbox.json")); err == nil {
			var cfg sandboxConfig
			if json.Unmarshal(b, &cfg) == nil {
				image = filepath.Base(cfg.Image)
				if cfg.RW {
					image += " (rw)"
				}
			}
		}
		fmt.Printf("%-20s %-10s %-8s %s\n", name, state, pidStr, image)
	}
	return 0
}

func cmdStop(name string) int {
	pid, alive := sandboxPID(name)
	if !alive {
		fmt.Fprintf(os.Stderr, "gantry stop: sandbox %q is not running\n", name)
		return 1
	}
	procTerminate(pid)
	for i := 0; i < 50; i++ {
		if !procAlive(pid) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if procAlive(pid) {
		procKill(pid)
	}
	// kill the sandbox's gvproxy too (defers don't run if the daemon was
	// SIGKILLed, orphaning it)
	dir := sandboxDir(name)
	if b, err := os.ReadFile(filepath.Join(dir, "gvproxy.pid")); err == nil {
		var gpid int
		if fmt.Sscanf(string(b), "%d", &gpid); gpid > 0 {
			procKill(gpid)
		}
	}
	// clean runtime files, keep sandbox.json so `start` can recreate
	for _, f := range []string{"vmm.pid", "gvproxy.pid", "ready", "ctl.sock", "1025.sock", "listen-1026.sock", "net.sock", "net.sock.client", "gvproxy-api.sock", "shares.json"} {
		os.Remove(filepath.Join(dir, f))
	}
	fmt.Printf("gantry stop: sandbox %q stopped\n", name)
	return 0
}

func cmdDelete(name string) int {
	if _, alive := sandboxPID(name); alive {
		if rc := cmdStop(name); rc != 0 {
			return rc
		}
	}
	if err := os.RemoveAll(sandboxDir(name)); err != nil {
		fmt.Fprintln(os.Stderr, "gantry delete:", err)
		return 1
	}
	fmt.Printf("gantry delete: sandbox %q deleted\n", name)
	return 0
}

// ---------------- shared helpers ---------------------------------------------

func absPath(p string) string {
	if abs, err := filepath.Abs(p); err == nil {
		return abs
	}
	return p
}

func dumpTail(path string) {
	b, err := os.ReadFile(path)
	if err != nil || len(b) == 0 {
		return
	}
	if len(b) > 4096 {
		b = b[len(b)-4096:]
	}
	fmt.Fprintf(os.Stderr, "---- last bytes of %s ----\n%s\n----\n", filepath.Base(path), b)
}
