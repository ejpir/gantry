package sandbox

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ejpir/gantry/internal/netpol"
	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/control"
	"github.com/ejpir/gantry/internal/sandbox/credhelper"
	"github.com/ejpir/gantry/internal/sandbox/localsec"
	"github.com/ejpir/gantry/internal/sandbox/oauthbridge"
	"github.com/ejpir/gantry/internal/sandbox/oauthtokens"
)

func (d *daemonSupervisor) startControl() error {
	if d.host.networkTx == nil {
		d.host.networkTx = control.NewNetworkTransactionCoordinator()
	}
	d.control.signals = make(chan os.Signal, 1)
	d.control.shutdown = make(chan struct{}, 1)
	signal.Notify(d.control.signals, syscall.SIGINT, syscall.SIGTERM)

	path := filepath.Join(d.dir, "ctl.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	// Protect and verify the endpoint before publishing it to the broker. The
	// Windows implementation installs a protected DACL instead of relying on
	// os.FileMode, which does not define local-account access there.
	if err := localsec.SecureEndpoint(path); err != nil {
		_ = listener.Close()
		_ = os.Remove(path)
		return fmt.Errorf("secure control endpoint: %w", err)
	}
	d.control.listener = listener

	var streamDial func() (net.Conn, error)
	if runner := d.guest.runnerBorrow(); runner != nil {
		// Sessions cross the worker bridge: no host listen-1026.sock exists
		// in the split topology.
		streamDial = func() (net.Conn, error) { return runner.DialStream(1026) }
	}
	liveNetworkPolicy := d.host.network.Policy
	if liveNetworkPolicy == nil {
		// Networking-disabled sandboxes still need a stable effective policy for
		// the host credential egress gate when organization policy changes live.
		liveNetworkPolicy = netpol.DefaultPolicy()
	}
	d.control.broker = &broker{
		cfg:            d.cfg,
		dir:            d.dir,
		rpc:            d.guest.rpcBorrow(),
		streamSock:     filepath.Join(d.dir, "listen-1026.sock"),
		streamDial:     streamDial,
		secretStore:    d.secretStore,
		store:          d.host.config(),
		shares:         d.host.shareBorrow(),
		ports:          d.host.portBorrow(),
		netPolicy:      control.NewNetworkPolicyManagerWithCoordinator(d.host.store, d.host.network.Backend, liveNetworkPolicy, d.host.networkTx),
		capture:        packetCaptureBackendFor(d.host.networkBorrow(), d.guest.packetCaptureBorrow()),
		guestToolsDone: make(chan struct{}),
		ideToolsDone:   make(chan struct{}),
		sessions:       map[string]chan struct{}{},
		sessionCtl:     map[string]net.Conn{},
		shutdown:       d.control.shutdown,
		audit:          d.host.audit,
	}
	d.control.broker.devContainers.Store(d.cfg.DevContainers)
	d.control.broker.configure = d.configureSandbox
	d.control.broker.policyApply = d.applyOrganizationPolicy
	d.secretStore.SetLogger(d.control.broker.auditf)
	// The OAuth bridge replays callbacks through the generic internal exec,
	// with its own response limit and op attribution bound here.
	d.control.broker.oauth = oauthbridge.New(func(stdin io.Reader, args []string, timeout time.Duration) ([]byte, int, error) {
		return d.control.broker.internalExec(stdin, args, timeout,
			oauthbridge.MaxReplayResponseSize, "oauth callback replay")
	}, d.control.broker.cfg.OAuthBridgeEnabled())
	// Credential broker: guest helpers reach it over vsock (the VMM dials
	// <dir>/1027.sock when a guest connects to the broker port). The egress
	// gate follows the live policy object.
	d.control.broker.domainAllowed = d.control.broker.netPolicy.DomainAllowed
	credLn, err := net.Listen("unix", filepath.Join(d.dir, credhelper.SockName))
	if err != nil {
		return fmt.Errorf("credential broker listener: %w", err)
	}
	// credhelper decision lines self-prefix "credhelper: ".
	d.control.broker.cred = credhelper.New(d.control.broker.resolveCredential, d.credentialAllowed, d.control.broker.auditf)
	// OAuth custody (opt-in): the daemon completes guest-initiated logins
	// host-side, holds refresh tokens (0600 disk sync under the sandbox
	// dir for restart durability), and pushes fresh access tokens into
	// the guest. Requires the callback bridge to intercept callbacks.
	if err := config.NormalizeOAuthProviders(&d.cfg); err != nil {
		_ = credLn.Close()
		return err
	}
	d.control.broker.cfg.OAuthProviders = d.cfg.OAuthProviders
	if d.cfg.OAuthCustodyEnabled() {
		if d.control.broker.oauth == nil {
			_ = credLn.Close()
			return fmt.Errorf("oauth custody requires an active OAuth callback bridge")
		}
		registry := oauthtokens.New()
		registry.AttachFile(d.dir)
		registry.SetLogger(func(f string, a ...any) { d.control.broker.auditf("oauth tokens: "+f, a...) })
		d.control.broker.custodyRegistry = registry
		cm := newCustodyManager(d.control.broker, registry)
		d.control.broker.cred.SetOAuthHandler(cm.handleOAuthOp)
		d.control.broker.oauth.SetCustodyConsumer(cm.consumeCallback)
		cm.restoreRestart()
		fmt.Printf("daemon: oauth custody enabled (refresh tokens held host-side)\n")
	}
	// MCP gateway (opt-in): vsock-bridged session mux with contained
	// local servers (docs/mcp-gateway.md).
	if err := d.startMCPGateway(); err != nil {
		_ = credLn.Close()
		return err
	}
	if d.cfg.SSH {
		if err := d.startSSHGateway(); err != nil {
			_ = credLn.Close()
			return err
		}
	}
	d.control.credListener = credLn
	if !d.control.servers.start(func(ctx context.Context) { _ = d.control.broker.cred.ServeContext(ctx, credLn) }) {
		return fmt.Errorf("credential broker background owner is closed")
	}
	if !d.control.servers.start(func(ctx context.Context) { d.control.broker.serveOwned(ctx, listener, &d.control.servers) }) {
		return fmt.Errorf("control broker background owner is closed")
	}
	return nil
}

func (d *daemonSupervisor) supervise() int {
	workerDead := closedWhenNetworkWorkerExits(d.host.networkBorrow())
	vmmDead := closedWhenVMMWorkerExits(d.guest.runnerBorrow())
	var expiryTimer *time.Timer
	defer func() {
		if expiryTimer != nil {
			expiryTimer.Stop()
		}
	}()

	for {
		var policyExpiry <-chan time.Time
		if deadline := d.governance.ExpiresAt(); !deadline.IsZero() {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				current := d.governance.ExpiresAt()
				if current.IsZero() || current.After(deadline) {
					continue
				}
				return d.gracefulStop("organization policy expired")
			}
			if expiryTimer == nil {
				expiryTimer = time.NewTimer(remaining)
			} else {
				if !expiryTimer.Stop() {
					select {
					case <-expiryTimer.C:
					default:
					}
				}
				expiryTimer.Reset(remaining)
			}
			policyExpiry = expiryTimer.C
		} else if expiryTimer != nil {
			if !expiryTimer.Stop() {
				select {
				case <-expiryTimer.C:
				default:
				}
			}
		}

		select {
		case <-policyExpiry:
			// A replacement can race the previous timer becoming ready. Recheck
			// the currently published engine before stopping for stale expiry.
			deadline := d.governance.ExpiresAt()
			if deadline.IsZero() || time.Now().Before(deadline) {
				continue
			}
			return d.gracefulStop("organization policy expired")
		case <-d.policyChanged:
			continue
		case sig := <-d.control.signals:
			return d.gracefulStop("signal " + sig.String())
		case <-d.control.shutdown:
			return d.gracefulStop("control request")
		case err := <-d.guest.exited():
			fmt.Fprintln(os.Stderr, "daemon: VM exited:", err)
			return 1
		case <-workerDead:
			// Losing the network worker also loses the policy enforcement point.
			// A VMM death closes the network data socket and can make both worker
			// notifications ready together. Give the VMM watcher a brief chance to
			// publish its authoritative process state so we do not report the
			// dependent network EOF as the root cause.
			if waitForClosed(vmmDead, 100*time.Millisecond) {
				fmt.Fprintln(os.Stderr, "daemon: vmm worker died:", d.guest.runnerBorrow().Err())
				fmt.Fprintln(os.Stderr, "daemon: network worker also died:", d.host.network.Worker.Err())
			} else {
				fmt.Fprintln(os.Stderr, "daemon: network worker died:", d.host.network.Worker.Err())
			}
			return 1
		case <-vmmDead:
			fmt.Fprintln(os.Stderr, "daemon: vmm worker died:", d.guest.runnerBorrow().Err())
			return 1
		}
	}
}

func waitForClosed(done <-chan struct{}, timeout time.Duration) bool {
	if done == nil {
		return false
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
		return true
	case <-timer.C:
		return false
	}
}

func closedWhenNetworkWorkerExits(network networkBorrow) <-chan struct{} {
	if network == nil {
		return nil
	}
	worker := network.workerBorrow()
	if worker == nil {
		return nil
	}
	return worker.Done()
}

func closedWhenVMMWorkerExits(runner guestRunnerBorrow) <-chan struct{} {
	if runner == nil {
		return nil
	}
	return runner.Done()
}

func (d *daemonSupervisor) gracefulStop(reason string) int {
	// Record shutdown before closing admission and beginning potentially slow
	// guest and device flushes. Deferred teardown observes the same idempotent
	// stopping phase.
	d.lifecycle.beginStop()
	fmt.Println("daemon:", reason, "— shutting down")
	d.control.closeAdmission() // no new broker sessions
	// The OAuth watcher and guest-tool delivery own internal RPC sessions and
	// temporary shares. Stop them before syncing or closing VM devices; deferred
	// close repeats this safely before releasing their dependencies.
	d.stopOAuthListenerWatch()
	d.stopGuestToolsDelivery()

	// Process exit is a power cut for the guest. Flush while the RPC
	// connection is still held: guest filesystem first (bounded because it
	// may be wedged), then host-side devices.
	if err := d.guest.sync(5 * time.Second); err != nil {
		fmt.Fprintln(os.Stderr, "daemon: guest filesystem sync:", err)
	}
	shutdownErr := d.closeShutdownDevices()
	if shutdownErr != nil {
		fmt.Fprintln(os.Stderr, "daemon: device shutdown:", shutdownErr)
		return 1
	}
	fmt.Println("daemon: shutdown complete")
	return 0
}

// closeShutdownDevices preserves the dependency order between the network
// enforcement point and the VM. A split network worker must answer its
// shutdown RPC while the packet link is still alive so the supervisor can
// merge the worker's final traffic epoch. External gvproxy is likewise
// stopped first so its expected peer EOF is quiet. Monolithic networking is
// owned by the VM and remains live until device teardown.
func (d *daemonSupervisor) closeShutdownDevices() error {
	return errors.Join(d.host.closeShutdownNetwork(), d.closeVMDevices())
}

func (d *daemonSupervisor) closeVMDevices() error {
	return d.guest.closeDevices()
}
