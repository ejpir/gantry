package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"gantry/internal/client"
	"gantry/internal/sandbox"
	"gantry/internal/secret"
	"gantry/internal/vmm"
)

// cmdExec is the sbx-style single-command flow: boot a VM (with gvproxy
// networking, like scripts/run-macos.sh container) and immediately start an
// interactive container session — one terminal, one process:
//
//	gantry exec                      # full Debian, writable root, bash
//	gantry exec -- /bin/sh           # pick the command
//	gantry exec -image artifacts/shell-rootfs.erofs -- /bin/sh
//	gantry exec -share code=$HOME/repos,ro
//	gantry exec -net=false -console  # no gvproxy; watch the guest boot
//
// hostctl + scripts/run-macos.sh remain for the two-terminal debug flow.
func cmdExec(argv []string) { os.Exit(runExec(argv)) }

func runExec(argv []string) int {
	fs := flag.NewFlagSet("exec", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, `usage: gantry exec [flags] [-- CMD]

One-shot: boot a VM on an OCI image and run CMD (default: the image's
entrypoint+cmd, else /bin/sh) attached to this terminal.

examples:
  gantry exec -image alpine:latest
  gantry exec -image debian:bookworm-slim -- apt list --installed
  gantry exec -image ./my-rootfs.erofs -share code=$HOME/repos,ro
  gantry exec -runtime runsc -image alpine:latest
  gantry exec -net=false -console

flags:`)
		fs.PrintDefaults()
	}
	rf := sandbox.RegisterRunFlags(fs)
	console := fs.Bool("console", false, "stream the guest serial console to stderr (default: log file in the work dir)")

	args := []string(nil)
	for i, a := range argv {
		if a == "--" {
			args = argv[i+1:]
			argv = argv[:i]
			break
		}
	}
	fs.Parse(argv)

	cfg, warnings, err := rf.Resolve(fs, func(format string, a ...any) {
		fmt.Printf("gantry exec: "+format+"\n", a...)
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "gantry exec:", err)
		return 1
	}
	for _, w := range warnings {
		fmt.Fprintln(os.Stderr, "gantry exec:", w)
	}
	secrets, _, err := rf.ResolveSecrets()
	if err != nil {
		fmt.Fprintln(os.Stderr, "gantry exec:", err)
		return 1
	}
	if len(secrets) > 0 && cfg.Net && cfg.NetPol == "" {
		fmt.Fprintf(os.Stderr, `gantry exec: %d secret(s) injected with the default egress policy (internet
allowed). Consider -net-policy with a domain allowlist so an injected
agent cannot send them anywhere.
`, len(secrets))
	}
	// No -- CMD: the image's Entrypoint+Cmd supplies the session command
	// (resolved in client.Session); a plain .erofs falls back to /bin/sh.
	hostShares, err := cfg.ParsedShares()
	if err != nil {
		fmt.Fprintln(os.Stderr, "gantry exec:", err)
		return 2
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
	consoleW := io.Writer(os.Stderr)
	if !*console {
		logf, err := os.Create(filepath.Join(tmp, "console.log"))
		if err != nil {
			fmt.Fprintln(os.Stderr, "gantry exec:", err)
			return 1
		}
		defer logf.Close()
		consoleW = logf
		fmt.Printf("gantry exec: guest console → %s (use -console to watch it live)\n", logf.Name())
	}

	// --- networking (embedded netstack; external gvproxy is an override) ---
	nw, err := cfg.StartNetwork(tmp)
	if err != nil {
		keepTmp = true
		fmt.Fprintf(os.Stderr, "gantry exec: %v (use -net=false to skip)\n", err)
		dumpLog("gvproxy.log")
		return 1
	}
	defer nw.Close()
	if nw.Policy != nil {
		fmt.Println("gantry exec: network policy:", nw.Policy.Describe())
	}

	// --- machine ------------------------------------------------------------
	opts, err := cfg.Opts(nw, hostShares, tmp, false)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gantry exec:", err)
		return 1
	}
	opts.Console = consoleW
	m, err := vmm.Prepare(opts)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gantry exec:", err)
		return 1
	}
	if err := vmm.WriteShareManifest(filepath.Join(tmp, "shares.json"), hostShares); err != nil {
		fmt.Fprintf(os.Stderr, "gantry exec: write share manifest: %v\n", err)
	}

	// Create the RPC listener before booting: vminitd makes one dial-back
	// attempt, so starting the VM first introduces a fast-boot race.
	rpcPath := filepath.Join(tmp, "1025.sock")
	rpcListener, err := client.ListenRPC(rpcPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gantry exec:", err)
		return 1
	}

	guestErr := make(chan error, 1)
	go func() { guestErr <- vmm.Run(m) }()

	// --- session ------------------------------------------------------------
	var taskStatus int // the command's exit status, propagated to ours
	shellErr := make(chan error, 1)
	go func() {
		shellErr <- client.Shell(client.ShellOptions{
			RPCSock:     rpcPath,
			RPCListener: rpcListener,
			StreamSock:  filepath.Join(tmp, "listen-1026.sock"),
			Share:       len(hostShares) > 0,
			RW:          cfg.RW,
			Args:        args,
			ImgCfg:      cfg.ImageCfg,
			Secrets:     secret.Env(secrets),
			ExitStatus:  &taskStatus,
		})
	}()

	select {
	case err := <-shellErr:
		fmt.Println("gantry exec: shutting down the VM")
		// Stop an external gvproxy before closing the VM's packet socket;
		// otherwise gvproxy logs the expected peer EOF as an ERROR during
		// normal teardown. Embedded networking remains open until m.Close.
		if nw.Sock != "" {
			nw.Close()
		}
		// The session already synced the guest (client.Shell, RW mode);
		// flush/close the devices host-side too — process exit alone is
		// a power cut that leaves flocks held and writes unflushed
		// (review finding 5).
		if cerr := m.Close(); cerr != nil {
			fmt.Fprintf(os.Stderr, "gantry exec: device shutdown: %v\n", cerr)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "gantry exec: %v\n", err)
			return 1
		}
		if taskStatus != 0 {
			// `gantry exec -- false` must fail: the task's exit status is
			// the command's result, not a transport detail.
			return taskStatus
		}
	case gerr := <-guestErr:
		_ = rpcListener.Close()
		keepTmp = true
		fmt.Fprintf(os.Stderr, "gantry exec: VM exited before the session started: %v\n", gerr)
		dumpLog("console.log")
		dumpLog("gvproxy.log")
		return 1
	}
	return 0
}
