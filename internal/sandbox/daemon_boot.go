package sandbox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ejpir/gantry/internal/client"
	"github.com/ejpir/gantry/internal/gutil"
	"github.com/ejpir/gantry/internal/sandbox/boundedlog"
	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/control"
	"github.com/ejpir/gantry/internal/sandbox/inspection"
	"github.com/ejpir/gantry/internal/sandbox/layout"
	"github.com/ejpir/gantry/internal/sandbox/localsec"
	"github.com/ejpir/gantry/internal/sandbox/vmmworker"
	"github.com/ejpir/gantry/internal/shares"
	"github.com/ejpir/gantry/internal/vmm"

	"github.com/containerd/ttrpc"
)

func (d *daemonSupervisor) load() error {
	// The secrets handshake arrives on stdin before anything else. Refuse a
	// malformed or oversized launcher handshake rather than silently starting
	// a sandbox without the secrets the caller expected to inject.
	secrets, sources, err := readSecretsHandshake(os.Stdin)
	if err != nil {
		return fmt.Errorf("secrets handshake: %w", err)
	}
	d.host.audit = &auditRing{}

	d.dir = layout.Dir(d.name)
	// Revalidate the local control boundary before reading configuration. On
	// Windows this replaces inherited ACLs and fails closed if ownership or
	// descriptor verification cannot establish a current-user-only directory.
	if err := localsec.SecureDir(d.dir); err != nil {
		return fmt.Errorf("sandbox directory security: %w", err)
	}
	// Acquire the daemon's authoritative lifetime lock before reading mutable
	// state. The launcher retains its stable, out-of-directory launch lock
	// until readiness or process exit, so the two locks overlap during handoff.
	lock, err := layout.HoldLock(d.dir)
	if err != nil {
		return fmt.Errorf("another daemon holds the sandbox lock: %w", err)
	}
	d.host.lock = lock
	// Publish the pid only with the lifetime lock held: layout.PID treats a
	// live pid as proof of life solely while vmm.lock is held, so a pid
	// recycled after an early daemon death is never mistaken for a daemon.
	if err := os.WriteFile(filepath.Join(d.dir, "vmm.pid"), []byte(fmt.Sprint(os.Getpid())), 0o600); err != nil {
		return fmt.Errorf("record daemon pid: %w", err)
	}
	store, err := config.LoadConfigStore(d.dir)
	if err != nil {
		return fmt.Errorf("config store: %w", err)
	}
	d.host.store = store
	d.cfg = d.host.config().Snapshot()
	if err := d.loadOrganizationPolicy(); err != nil {
		return err
	}
	if !sameSecretSources(sources, d.cfg.SecretSources) {
		return fmt.Errorf("secrets handshake sources do not match the persisted sandbox configuration")
	}
	// Validate the sources actually received over stdin, not only their
	// persisted descriptions. Normal launch keeps them identical; this second
	// check also closes manual-daemon or future handshake-divergence paths.
	actualSources := d.cfg
	actualSources.SecretSources = sources
	if err := config.ValidateSecretSourceIsolation(actualSources); err != nil {
		return fmt.Errorf("secrets handshake isolation: %w", err)
	}
	d.secretStore = newSecretStore(secrets, sources, func(f string, a ...any) {
		d.host.audit.logf(d.dir, f, a...)
	})
	if d.cfg.ImageDigest != "" && !gutil.FileExists(d.cfg.Image) {
		return fmt.Errorf("image %s not in cache; run `gantry image pull %s`", d.cfg.ImageDigest, d.cfg.ImageRef)
	}
	if d.cfg.DevContainers {
		if !gutil.FileExists(d.cfg.DevContainersImage) || d.cfg.DevContainersImageCfg == nil {
			return fmt.Errorf("dev containers IDE image is not prepared; resume the sandbox through Gantry")
		}
		if !gutil.FileExists(d.cfg.DevContainersRWLayer) {
			return fmt.Errorf("dev containers writable layer is not prepared; resume the sandbox through Gantry")
		}
	}
	return nil
}

func (d *daemonSupervisor) startHostServices() error {
	consoleLog, err := boundedlog.NewPipe(filepath.Join(d.dir, "console.log"))
	if err != nil {
		return fmt.Errorf("console log broker: %w", err)
	}
	d.host.consoleLog = consoleLog
	d.host.console = consoleLog.Writer()
	network, err := startNetworkWithGovernance(d.cfg, d.dir, d.governance.Snapshot())
	if err != nil {
		return err
	}
	d.host.network = network
	d.bootLog("network up")
	d.logNetworkState()

	shareManager, warnings, err := control.NewShareManagerWithController(d.dir, d.host.store, d.governance)
	if err != nil {
		return fmt.Errorf("shares: %w", err)
	}
	d.host.shares = shareManager
	for _, warning := range warnings {
		fmt.Fprintln(os.Stderr, "daemon: shares:", warning)
	}
	if d.host.networkTx == nil {
		d.host.networkTx = control.NewNetworkTransactionCoordinator()
	}
	d.host.ports = control.NewPortManagerWithCoordinator(d.host.store, d.host.network.Backend, d.host.networkTx)
	return nil
}

func (d *daemonSupervisor) logNetworkState() {
	if d.host.network.Policy != nil {
		fmt.Fprintln(os.Stderr, "daemon: network policy:", d.host.network.Policy.Describe())
	}
	for _, degraded := range d.host.network.Degraded {
		fmt.Fprintln(os.Stderr, "daemon: process isolation degraded:", degraded)
	}
	if d.host.network.Split {
		d.bootLog("network worker: split process (data/control channels up)")
	}
}

func (d *daemonSupervisor) prepareGuest() error {
	opts, err := d.host.vmmOptions(d.cfg, d.dir, true)
	if err != nil {
		return err
	}
	if d.bootTiming {
		// The same origin travels into a split VMM worker, letting its
		// low-overhead device milestones line up with daemon readiness.
		opts.BootTimingStart = d.started
	}
	if err := d.prepareVM(opts); err != nil {
		return err
	}
	d.bootLog("machine prepared (RAM+kernel)")

	if err := d.writeIsolationState(); err != nil {
		fmt.Fprintln(os.Stderr, "daemon: isolation state:", err)
	}
	if err := d.host.shareBorrow().Publish(); err != nil {
		return fmt.Errorf("share manifest: %w", err)
	}
	return nil
}

func (d *daemonSupervisor) writeIsolationState() error {
	confinement, _ := d.guest.confinementReport()
	mcpConfinement, _ := d.control.mcp.confinementReport()
	return writeIsolationState(d.dir, d.cfg, d.host.network, d.guest.runnerBorrow() != nil, confinement, mcpConfinement)
}

func (d *daemonSupervisor) prepareVM(opts vmm.Opts) error {
	// Split VMM (Phase 2): the guest runs in a _vmm-worker process; the
	// supervisor keeps ctl.sock, sessions, policy, and all host sockets.
	runner, splitErr := vmmworker.TryStart(d.cfg, opts, d.host.networkBorrow().vmmAttachment(), d.host.shareBorrow(), d.dir, d.host.console)
	switch {
	case splitErr == nil:
		d.guest.setRunner(runner)
		if err := d.installPolicyFanout(); err != nil {
			return err
		}
		d.bootLog("vmm worker spawned (split topology)")
		return nil
	case d.cfg.ProcessIsolation == "required":
		return fmt.Errorf("-process-isolation=required but the split VMM failed: %w", splitErr)
	case !errors.Is(splitErr, vmmworker.ErrUnavailable):
		fmt.Fprintf(os.Stderr, "daemon: split VMM failed (%v), falling back to monolithic\n", splitErr)
	}

	if hub := d.host.shareBorrow().Hub(); hub != nil {
		opts.Filesystems = []vmm.Filesystem{{
			Tag:         shares.HubTag,
			Handler:     hub,
			Description: "share hub (hot-add enabled)",
		}}
	}
	opts.Console = d.host.console
	machine, err := vmm.Prepare(opts)
	if err != nil {
		return err
	}
	d.guest.setMachine(machine)
	return nil
}

func (d *daemonSupervisor) installPolicyFanout() error {
	if d.host.network == nil || d.host.network.Split || d.host.network.Backend == nil {
		return nil
	}
	pusher := d.guest.policyPusherBorrow()
	if pusher == nil {
		return nil
	}
	fanout, err := control.NewVMMPolicyBackend(d.host.network.Backend, pusher, d.host.network.Policy, d.guest.closeDevices)
	if err != nil {
		return fmt.Errorf("initialize VMM policy fan-out: %w", err)
	}
	d.host.network.Backend = fanout
	return nil
}

type guestRPCResult struct {
	client *ttrpc.Client
	err    error
}

func (d *daemonSupervisor) connectGuest() error {
	// Create the RPC listener before booting: vminitd makes one dial-back
	// attempt, and a fast CI VM can otherwise beat net.Listen below.
	rpcSock := filepath.Join(d.dir, "1025.sock")
	listener, err := client.ListenRPC(rpcSock)
	if err != nil {
		return err
	}

	guestErr := d.guest.start()
	d.bootLog("vCPUs running; guest booting")

	// Hold the single dial-back connection for the VM's lifetime, while also
	// watching guestErr so a failed boot cannot strand CmdStart until timeout.
	rpcCh := make(chan guestRPCResult, 1)
	if !d.guest.workers.start(func(context.Context) {
		rpc, err := client.AcceptRPCListener(listener, rpcSock)
		rpcCh <- guestRPCResult{client: rpc, err: err}
	}) {
		_ = listener.Close()
		return fmt.Errorf("guest plane is stopping")
	}
	select {
	case result := <-rpcCh:
		if result.err != nil {
			return result.err
		}
		d.guest.setRPC(result.client)
		return nil
	case err := <-guestErr:
		_ = listener.Close()
		return fmt.Errorf("VM exited before guest RPC: %v", err)
	}
}

func (d *daemonSupervisor) publishReady() error {
	if phase := d.lifecycle.Phase(); phase != daemonControlReady {
		return fmt.Errorf("refusing to publish readiness from daemon phase %s", phase)
	}
	if d.control.listener == nil || d.control.broker == nil {
		return fmt.Errorf("refusing to publish readiness before the control broker is listening")
	}
	if err := inspection.PublishActive(d.dir, d.cfg); err != nil {
		return fmt.Errorf("publish active sandbox settings: %w", err)
	}
	// Keep the historical timing label, but record it only after startControl
	// has installed ctl.sock and launched the broker accept loop. startControl
	// also launched the effective MCP worker, so a saved restart marker is now
	// satisfied and can be cleared before the dashboard observes readiness.
	d.bootLog("guest RPC connected (READY)")
	if err := os.Remove(filepath.Join(d.dir, config.MCPRestartMarker)); err != nil && !os.IsNotExist(err) {
		fmt.Fprintln(os.Stderr, "daemon: clear MCP restart marker:", err)
	}
	if err := os.WriteFile(filepath.Join(d.dir, "ready"), []byte("1\n"), 0o600); err != nil {
		return fmt.Errorf("publish daemon readiness: %w", err)
	}
	if err := d.lifecycle.advance(daemonReady); err != nil {
		return err
	}
	if err := notifyDaemonReady(d.readySocket); err != nil {
		// The parent may have exited or fallen back to ready-file polling;
		// readiness notification is never a reason to stop a healthy VM.
		fmt.Fprintln(os.Stderr, "daemon: parent readiness notification:", err)
	}
	fmt.Println("daemon: guest RPC connection held; broker on ctl.sock")
	// Readiness is the contract boundary for the small-boot-memory design.
	// Publish both durable and event-driven readiness before asking Linux to
	// online the configured tail; the request may immediately consume a guest
	// CPU for memory-block initialization, but must never delay the launcher.
	d.background.start(func(context.Context) {
		if err := d.guest.requestHotMemory(); err != nil {
			fmt.Fprintln(os.Stderr, "daemon: request post-readiness guest memory:", err)
		}
	})
	return nil
}
