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
	flags.Usage = func() { _, _ = fmt.Fprintln(flags.Output(), "usage: gantry update") }
	if err := flags.Parse(argv); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 {
		flags.Usage()
		return 2
	}
	result, err := selfupdate.Apply(context.Background(), func(format string, values ...any) {
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
	_, _ = fmt.Fprintf(os.Stdout, "updated Gantry %s → %s in %s\n", result.Previous, result.Installed, result.Executable)
	return 0
}

const (
	// updateCheckTimeout bounds the release lookup itself.
	updateCheckTimeout = 30 * time.Second
	// updateCheckGrace bounds how long exiting waits on a lookup that has not
	// finished. Most commands outlast the request, so this rarely applies.
	updateCheckGrace = time.Second
)

// updateCheck is a release-status refresh running alongside the command the
// user actually asked for.
//
// It used to run in a detached child process with a hidden window, started as
// the parent exited. A program silently spawning a windowless copy of itself
// that then reaches out to the network is a shape endpoint protection treats
// as malicious, and it bought nothing that a goroutine cannot do: the check is
// one HTTP request whose only output is a cache file read by the next run.
type updateCheck struct {
	done   chan struct{}
	cancel context.CancelFunc
}

// startUpdateCheck begins a refresh if the cached status is stale. It runs
// concurrently with the command so the lookup costs no wall clock of its own.
func startUpdateCheck(argv []string) *updateCheck {
	if !selfupdate.Enabled() || skipUpdateNotice(argv) || !term.IsTerminal(int(os.Stderr.Fd())) {
		return nil
	}
	if _, _, fresh := selfupdate.Cached(); fresh {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), updateCheckTimeout)
	check := &updateCheck{done: make(chan struct{}), cancel: cancel}
	go func() {
		defer close(check.done)
		_, _ = selfupdate.Refresh(ctx)
	}()
	return check
}

// wait gives an unfinished check a short grace period so its result reaches
// the cache. Gantry's exit status never depends on it, so an unreachable
// GitHub costs updateCheckGrace and nothing else.
func (c *updateCheck) wait() {
	if c == nil {
		return
	}
	defer c.cancel()
	select {
	case <-c.done:
	case <-time.After(updateCheckGrace):
	}
}

func maybeNotifyUpdate(argv []string, statusCode int, check *updateCheck) {
	// The in-process refresh starts optimistically so it can overlap a valid
	// command. Once that command fails, preserve the prompt error path: cancel
	// the concurrent lookup instead of imposing an exit grace period on a
	// command that cannot display an update notice anyway.
	if statusCode != 0 {
		if check != nil {
			check.cancel()
		}
		return
	}
	check.wait()
	if !selfupdate.Enabled() || !term.IsTerminal(int(os.Stderr.Fd())) || skipUpdateNotice(argv) {
		return
	}
	// A check that finished during this run has already updated the cache, so
	// a new release can be reported in the run that discovered it.
	if status, _, _ := selfupdate.Cached(); status.Available {
		fmt.Fprintf(os.Stderr, "\nUpdate available: Gantry %s (current %s). Run `gantry update`.\n", status.Latest, status.Current)
	}
}

func skipUpdateNotice(argv []string) bool {
	if len(argv) == 0 {
		return true // the TUI performs its own asynchronous check
	}
	switch argv[0] {
	case "tui", "version", "update", "serve", "daemon", "_net-worker", "_vmm-worker":
		return true
	default:
		return false
	}
}
