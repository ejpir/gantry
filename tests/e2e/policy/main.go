// policy is a black-box organization-policy battery. The normal mode boots
// real VMs; go test exercises the harness and fixtures without a hypervisor.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
)

type options struct {
	gantry, kernel, rootfs, image, artifacts, workDir string
	timeout, expiryWindow                             time.Duration
	cliOnly, keep                                     bool
}

func main() {
	var opts options
	flag.StringVar(&opts.gantry, "gantry", "", "Gantry executable under test (required)")
	flag.StringVar(&opts.kernel, "kernel", "", "guest kernel (required for VM tests)")
	flag.StringVar(&opts.rootfs, "rootfs", "", "guest Nerdbox rootfs (required for VM tests)")
	flag.StringVar(&opts.image, "image", "", "local workload EROFS image (required for VM tests)")
	flag.StringVar(&opts.artifacts, "artifacts", "", "directory containing the current gantry-guest helper")
	flag.StringVar(&opts.workDir, "work-dir", "", "parent for a private test workspace (default: short temporary path)")
	flag.DurationVar(&opts.timeout, "timeout", 12*time.Minute, "overall battery deadline")
	flag.DurationVar(&opts.expiryWindow, "expiry-window", 90*time.Second, "signed lifetime for the runtime-expiry test (minimum 30s)")
	flag.BoolVar(&opts.cliOnly, "cli-only", false, "only verify bundles and offline decisions; does NOT count as a VM battery")
	flag.BoolVar(&opts.keep, "keep", false, "preserve the workspace after success (failures always preserve logs)")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "unexpected positional arguments")
		os.Exit(2)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, opts); err != nil {
		fmt.Fprintln(os.Stderr, "Policy E2E:", err)
		os.Exit(1)
	}
}

func run(parent context.Context, opts options) (runErr error) {
	if opts.timeout <= 0 || opts.expiryWindow < 30*time.Second {
		return fmt.Errorf("timeout must be positive and expiry-window at least 30s")
	}
	h, err := newHarness(opts)
	if err != nil {
		return err
	}
	fmt.Println("policy workspace:", h.root)
	defer func() {
		if err := h.cleanup(); err != nil && runErr == nil {
			runErr = err
		}
		if runErr == nil && !opts.keep {
			if err := os.RemoveAll(h.root); err != nil {
				runErr = err
			}
		} else {
			fmt.Println("preserved policy workspace:", h.root)
		}
	}()
	ctx, cancel := context.WithTimeout(parent, opts.timeout)
	defer cancel()
	allowed := newEndpoint("OPA-ALLOWED-ENDPOINT")
	defer allowed.Close()
	denied := newEndpoint("OPA-DENIED-ENDPOINT")
	defer denied.Close()
	fixtures, err := newFixtures(h.root, allowed.port(), denied.port())
	if err != nil {
		return err
	}
	h.fixtures = fixtures
	if err := h.offline(ctx); err != nil {
		return err
	}
	if opts.cliOnly {
		fmt.Printf("Policy CLI: %d checks passed (VM tests not run)\n", h.checks)
		return nil
	}
	if err := h.enforcement(ctx, allowed, denied); err != nil {
		return err
	}
	if err := h.expiry(ctx, opts.expiryWindow); err != nil {
		return err
	}
	fmt.Printf("Policy E2E: %d checks passed\n", h.checks)
	return nil
}
