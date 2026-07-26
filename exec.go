package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"gantry/internal/client"
	"gantry/internal/sandbox"
	"gantry/internal/vmm"
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

	guestErr := make(chan error, 1)
	go func() { guestErr <- vmm.Run(m) }()

	// --- session ------------------------------------------------------------
	shellErr := make(chan error, 1)
	go func() {
		shellErr <- client.Shell(client.ShellOptions{
			RPCSock:    filepath.Join(tmp, "1025.sock"),
			StreamSock: filepath.Join(tmp, "listen-1026.sock"),
			Share:      len(hostShares) > 0,
			RW:         cfg.RW,
			Args:       args,
			ImgCfg:     cfg.ImageCfg,
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
