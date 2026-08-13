package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/ejpir/gantry/internal/gutil"
	"github.com/ejpir/gantry/internal/sandbox"
	"github.com/ejpir/gantry/internal/secret"
)

var transientExec = sandbox.CmdTransientExec

// runExec is the one-shot CLI. Runtime ownership lives in sandbox so this
// path and named sandboxes share the same supervisor/worker topology.
func runExec(argv []string) int {
	fs := flag.NewFlagSet("exec", flag.ContinueOnError)
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
	for i, arg := range argv {
		if arg == "--" {
			args = argv[i+1:]
			argv = argv[:i]
			break
		}
	}
	if err := fs.Parse(argv); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	progress := gutil.NewProgressPrinter(os.Stdout, "gantry exec: ")
	cfg, warnings, err := rf.Resolve(fs, progress.Printf)
	progress.Finish()
	if err != nil {
		fmt.Fprintln(os.Stderr, "gantry exec:", err)
		return 1
	}
	for _, warning := range warnings {
		fmt.Fprintln(os.Stderr, "gantry exec:", warning)
	}
	secrets, _, err := rf.ResolveSecrets()
	if err != nil {
		fmt.Fprintln(os.Stderr, "gantry exec:", err)
		return 1
	}
	warnOpenSecretEgress(cfg, secrets)
	return transientExec(cfg, secrets, args, *console)
}

func warnOpenSecretEgress(cfg sandbox.RunConfig, secrets map[string]secret.Value) {
	if len(secrets) == 0 || !cfg.Net || cfg.NetPol != "" {
		return
	}
	fmt.Fprintf(os.Stderr, `gantry exec: %d secret(s) injected with the default egress policy (internet
allowed). Consider -net-policy with a domain allowlist so an injected
agent cannot send them anywhere.
`, len(secrets))
}
