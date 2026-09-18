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
	"github.com/ejpir/gantry/internal/sandbox/guestplane"
	"github.com/ejpir/gantry/internal/sandbox/localsec"
	"github.com/ejpir/gantry/internal/sandbox/oauthbridge"
	"github.com/ejpir/gantry/internal/sandbox/oauthtokens"
)

func (d *daemonSupervisor) startControl() error {
	if d.host.Transactions() == nil {
		d.host.SetTransactions(control.NewNetworkTransactionCoordinator())
	}
	signals := make(chan os.Signal, 1)
	shutdown := make(chan struct{}, 1)
	d.control.SetSignals(signals)
	d.control.SetShutdown(shutdown)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

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
	d.control.SetListener(listener)

	var streamDial func() (net.Conn, error)
	if runner := d.guest.Runner(); runner != nil {
		// Sessions cross the worker bridge: no host listen-1026.sock exists
		// in the split topology.
		streamDial = func() (net.Conn, error) { return runner.DialStream(1026) }
	}
	liveNetworkPolicy := d.host.Network().Policy()
	if liveNetworkPolicy == nil {
		// Networking-disabled sandboxes still need a stable effective policy for
		// the host credential egress gate when organization policy changes live.
		liveNetworkPolicy = netpol.DefaultPolicy()
	}
	br := &broker{
		cfg:            d.cfg,
		dir:            d.dir,
		rpc:            d.guest.RPC(),
		streamSock:     filepath.Join(d.dir, "listen-1026.sock"),
		streamDial:     streamDial,
		secretStore:    d.secretStore,
		store:          d.host.Config(),
		shares:         d.host.Shares(),
		ports:          d.host.Ports(),
		netPolicy:      control.NewNetworkPolicyManagerWithCoordinator(d.host.Config(), d.host.Network().Backend(), liveNetworkPolicy, d.host.Transactions()),
		capture:        packetCaptureBackendFor(d.host.Network(), d.guest.PacketCapture()),
		guestToolsDone: make(chan struct{}),
		ideToolsDone:   make(chan struct{}),
		sessions:       map[string]chan struct{}{},
		sessionCtl:     map[string]net.Conn{},
		shutdown:       shutdown,
		audit:          d.host.Audit(),
	}
	d.control.SetBroker(br)
	br.devContainers.Store(d.cfg.DevContainers)
	br.configure = d.configureSandbox
	br.policyApply = d.applyOrganizationPolicy
	d.secretStore.SetLogger(br.auditf)
	// The OAuth bridge replays callbacks through the generic internal exec,
	// with its own response limit and op attribution bound here.
	br.oauth = oauthbridge.New(func(stdin io.Reader, args []string, timeout time.Duration) ([]byte, int, error) {
		return br.internalExec(stdin, args, timeout,
			oauthbridge.MaxReplayResponseSize, "oauth callback replay")
	}, br.cfg.OAuthBridgeEnabled())
	// Credential broker: guest helpers reach it over vsock (the VMM dials
	// <dir>/1027.sock when a guest connects to the broker port). The egress
	// gate follows the live policy object.
	br.domainAllowed = br.netPolicy.DomainAllowed
	credLn, err := net.Listen("unix", filepath.Join(d.dir, credhelper.SockName))
	if err != nil {
		return fmt.Errorf("credential broker listener: %w", err)
	}
	// credhelper decision lines self-prefix "credhelper: ".
	br.cred = credhelper.New(br.resolveCredential, d.credentialAllowed, br.auditf)
	// OAuth custody (opt-in): the daemon completes guest-initiated logins
	// host-side, holds refresh tokens (0600 disk sync under the sandbox
	// dir for restart durability), and pushes fresh access tokens into
	// the guest. Requires the callback bridge to intercept callbacks.
	if err := config.NormalizeOAuthProviders(&d.cfg); err != nil {
		_ = credLn.Close()
		return err
	}
	br.cfg.OAuthProviders = d.cfg.OAuthProviders
	if d.cfg.OAuthCustodyEnabled() {
		if br.oauth == nil {
			_ = credLn.Close()
			return fmt.Errorf("oauth custody requires an active OAuth callback bridge")
		}
		registry := oauthtokens.New()
		registry.AttachFile(d.dir)
		registry.SetLogger(func(f string, a ...any) { br.auditf("oauth tokens: "+f, a...) })
		br.custodyRegistry = registry
		cm := newCustodyManager(br, registry)
		br.cred.SetOAuthHandler(cm.handleOAuthOp)
		br.oauth.SetCustodyConsumer(cm.consumeCallback)
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
	d.control.SetCredentialListener(credLn)
	if !d.control.StartServer(func(ctx context.Context) { _ = br.cred.ServeContext(ctx, credLn) }) {
		return fmt.Errorf("credential broker background owner is closed")
	}
	if !d.control.StartServer(func(ctx context.Context) { br.serveOwned(ctx, listener, d.control.StartServer) }) {
		return fmt.Errorf("control broker background owner is closed")
	}
	return nil
}

func (d *daemonSupervisor) supervise() int {
	workerDead := closedWhenNetworkWorkerExits(d.host.Network())
	vmmDead := closedWhenVMMWorkerExits(d.guest.Runner())
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
		case sig := <-d.control.Signals():
			return d.gracefulStop("signal " + sig.String())
		case <-d.control.Shutdown():
			return d.gracefulStop("control request")
		case err := <-d.guest.Exited():
			fmt.Fprintln(os.Stderr, "daemon: VM exited:", err)
			return 1
		case <-workerDead:
			// Losing the network worker also loses the policy enforcement point.
			// A VMM death closes the network data socket and can make both worker
			// notifications ready together. Give the VMM watcher a brief chance to
			// publish its authoritative process state so we do not report the
			// dependent network EOF as the root cause.
			if waitForClosed(vmmDead, 100*time.Millisecond) {
				fmt.Fprintln(os.Stderr, "daemon: vmm worker died:", d.guest.Runner().Err())
				fmt.Fprintln(os.Stderr, "daemon: network worker also died:", d.host.Network().WorkerError())
			} else {
				fmt.Fprintln(os.Stderr, "daemon: network worker died:", d.host.Network().WorkerError())
			}
			return 1
		case <-vmmDead:
			fmt.Fprintln(os.Stderr, "daemon: vmm worker died:", d.guest.Runner().Err())
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
	worker := network.WorkerBorrow()
	if worker == nil {
		return nil
	}
	return worker.Done()
}

func closedWhenVMMWorkerExits(runner guestplane.Runner) <-chan struct{} {
	if runner == nil {
		return nil
	}
	return runner.Done()
}

func (d *daemonSupervisor) gracefulStop(reason string) int {
	// Record shutdown before closing admission and beginning potentially slow
	// guest and device flushes. Deferred teardown observes the same idempotent
	// stopping phase.
	d.lifecycle.BeginStop()
	fmt.Println("daemon:", reason, "— shutting down")
	d.control.CloseAdmission() // no new broker sessions
	// The OAuth watcher and guest-tool delivery own internal RPC sessions and
	// temporary shares. Stop them before syncing or closing VM devices; deferred
	// close repeats this safely before releasing their dependencies.
	d.stopOAuthListenerWatch()
	d.stopGuestToolsDelivery()

	// Process exit is a power cut for the guest. Flush while the RPC
	// connection is still held: guest filesystem first (bounded because it
	// may be wedged), then host-side devices.
	if err := d.guest.Sync(5 * time.Second); err != nil {
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
	return errors.Join(d.host.CloseShutdownNetwork(), d.closeVMDevices())
}

func (d *daemonSupervisor) closeVMDevices() error {
	return d.guest.CloseDevices()
}
