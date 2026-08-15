package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/ejpir/gantry/internal/selfupdate"
	"golang.org/x/term"
)

func cmdVersion(argv []string) int {
	if len(argv) > 0 {
		if len(argv) == 1 && (argv[0] == "-h" || argv[0] == "--help") {
			_, _ = fmt.Fprintln(os.Stdout, "usage: gantry version")
			return 0
		}
		fmt.Fprintln(os.Stderr, "usage: gantry version")
		return 2
	}
	_, _ = fmt.Fprintf(os.Stdout, "gantry %s\n", selfupdate.Current())
	if !selfupdate.Enabled() {
		return 0
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	status, err := selfupdate.Refresh(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gantry version: latest release unavailable:", err)
		return 0
	}
	if status.Available {
		_, _ = fmt.Fprintf(os.Stdout, "update available: %s (run `gantry update`)\n", status.Latest)
	} else {
		_, _ = fmt.Fprintln(os.Stdout, "latest release: up to date")
	}
	return 0
}

func cmdUpdate(argv []string) int {
	flags := flag.NewFlagSet("update", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	waitPID := flags.Int("wait-pid", 0, "process that must exit before replacing a locked executable")
	flags.Usage = func() { _, _ = fmt.Fprintln(flags.Output(), "usage: gantry update") }
	if err := flags.Parse(argv); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 || *waitPID < 0 {
		flags.Usage()
		return 2
	}
	result, err := selfupdate.Apply(context.Background(), *waitPID, func(format string, values ...any) {
		fmt.Fprintf(os.Stderr, format+"\n", values...)
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "gantry update:", err)
		return 1
	}
	if result.Installed == result.Previous {
		_, _ = fmt.Fprintf(os.Stdout, "gantry %s is already up to date\n", result.Installed)
		return 0
	}
	if result.Deferred {
		_, _ = fmt.Fprintf(os.Stdout, "gantry %s verified and staged; installation will finish when Gantry exits\n", result.Installed)
		return 0
	}
	_, _ = fmt.Fprintf(os.Stdout, "updated Gantry %s → %s in %s\n", result.Previous, result.Installed, result.Executable)
	return 0
}

func cmdUpdateCheck(argv []string) int {
	if len(argv) != 0 {
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, _ = selfupdate.Refresh(ctx)
	return 0
}

func maybeNotifyUpdate(argv []string, statusCode int) {
	if statusCode != 0 || !selfupdate.Enabled() || !term.IsTerminal(int(os.Stderr.Fd())) || skipUpdateNotice(argv) {
		return
	}
	status, _, fresh := selfupdate.Cached()
	if status.Available {
		fmt.Fprintf(os.Stderr, "\nUpdate available: Gantry %s (current %s). Run `gantry update`.\n", status.Latest, status.Current)
	}
	if !fresh {
		_ = startBackgroundUpdateCheck()
	}
}

func skipUpdateNotice(argv []string) bool {
	if len(argv) == 0 {
		return true // the TUI performs its own asynchronous check
	}
	switch argv[0] {
	case "tui", "version", "update", "serve", "daemon", "_update-check", "_net-worker", "_vmm-worker":
		return true
	default:
		return false
	}
}
