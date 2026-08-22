package sandbox

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/ejpir/gantry/internal/client"
	"github.com/ejpir/gantry/internal/sandbox/control"
	"github.com/ejpir/gantry/internal/sandbox/credhelper"
	"github.com/ejpir/gantry/internal/sandbox/localsec"
	"github.com/ejpir/gantry/internal/sandbox/oauthbridge"
	"github.com/ejpir/gantry/internal/sandbox/oauthtokens"
	"github.com/ejpir/gantry/internal/sandbox/vmmworker"
)

func (d *daemonRuntime) startControl() error {
	d.signals = make(chan os.Signal, 1)
	d.shutdown = make(chan struct{}, 1)
	signal.Notify(d.signals, syscall.SIGINT, syscall.SIGTERM)

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
	d.control = listener

	var streamDial func() (net.Conn, error)
	if d.runner != nil {
		// Sessions cross the worker bridge: no host listen-1026.sock exists
		// in the split topology.
		streamDial = func() (net.Conn, error) { return d.runner.DialStream(1026) }
	}
	d.broker = &broker{
		cfg:         d.cfg,
		dir:         d.dir,
		rpc:         d.rpc,
		streamSock:  filepath.Join(d.dir, "listen-1026.sock"),
		streamDial:  streamDial,
		secretStore: d.secretStore,
		store:       d.store,
		shares:      d.shares,
		ports:       d.ports,
		netPolicy:   control.NewNetworkPolicyManager(d.store, d.network.Backend, d.network.Policy),
		capture:     packetCaptureBackendFor(d.network, d.runner),
		sessions:    map[string]chan struct{}{},
		sessionCtl:  map[string]net.Conn{},
		shutdown:    d.shutdown,
		audit:       d.audit,
	}
	d.secretStore.SetLogger(d.broker.auditf)
	// The OAuth bridge replays callbacks through the generic internal exec,
	// with its own response limit and op attribution bound here.
	d.broker.oauth = oauthbridge.New(func(args []string, timeout time.Duration) ([]byte, int, error) {
		return d.broker.internalExec(strings.NewReader(""), args, timeout,
			oauthbridge.MaxReplayResponseSize, "oauth callback replay")
	}, d.broker.cfg.OAuthBridgeEnabled())
	// Credential broker: guest helpers reach it over vsock (the VMM dials
	// <dir>/1027.sock when a guest connects to the broker port). The egress
	// gate follows the live policy object.
	if d.network != nil && d.network.Policy != nil {
		d.broker.domainAllowed = d.network.Policy.DomainAllowed
	}
	credLn, err := net.Listen("unix", filepath.Join(d.dir, credhelper.SockName))
	if err != nil {
		return fmt.Errorf("credential broker listener: %w", err)
	}
	// credhelper decision lines self-prefix "credhelper: ".
	d.broker.cred = credhelper.New(d.broker.resolveCredential, d.broker.domainAllowed, d.broker.auditf)
	// OAuth custody (opt-in): the daemon completes guest-initiated logins
	// host-side, holds refresh tokens (0600 disk sync under the sandbox
	// dir for restart durability), and pushes fresh access tokens into
	// the guest. Requires the callback bridge to intercept callbacks.
	if d.cfg.OAuthCustodyEnabled() {
		if d.broker.oauth == nil {
			_ = credLn.Close()
			return fmt.Errorf("oauth custody requires an active OAuth callback bridge")
		}
		registry := oauthtokens.New()
		registry.AttachFile(d.dir)
		registry.SetLogger(func(f string, a ...any) { d.broker.auditf("oauth tokens: "+f, a...) })
		d.broker.custodyRegistry = registry
		cm := newCustodyManager(d.broker, registry)
		d.broker.cred.SetOAuthHandler(cm.handleOAuthOp)
		d.broker.oauth.SetCustodyConsumer(cm.consumeCallback)
		cm.restoreRestart()
		fmt.Printf("daemon: oauth custody enabled (refresh tokens held host-side)\n")
	}
	// MCP gateway (opt-in): vsock-bridged session mux with contained
	// local servers (docs/mcp-gateway.md).
	if err := d.startMCPGateway(); err != nil {
		_ = credLn.Close()
		return err
	}
	go func() { _ = d.broker.cred.Serve(credLn) }()
	go d.broker.serve(listener)
	return nil
}

func (d *daemonRuntime) supervise() int {
	workerDead := closedWhenNetworkWorkerExits(d.network)
	vmmDead := closedWhenVMMWorkerExits(d.runner)

	select {
	case sig := <-d.signals:
		return d.gracefulStop("signal " + sig.String())
	case <-d.shutdown:
		return d.gracefulStop("control request")
	case err := <-d.guestErr:
		fmt.Fprintln(os.Stderr, "daemon: VM exited:", err)
		return 1
	case <-workerDead:
		// Losing the network worker also loses the policy enforcement point.
		// A VMM death closes the network data socket and can make both worker
		// notifications ready together. Give the VMM watcher a brief chance to
		// publish its authoritative process state so we do not report the
		// dependent network EOF as the root cause.
		if waitForClosed(vmmDead, 100*time.Millisecond) {
			fmt.Fprintln(os.Stderr, "daemon: vmm worker died:", d.runner.Err())
			fmt.Fprintln(os.Stderr, "daemon: network worker also died:", d.network.Worker.Err())
		} else {
			fmt.Fprintln(os.Stderr, "daemon: network worker died:", d.network.Worker.Err())
		}
		return 1
	case <-vmmDead:
		fmt.Fprintln(os.Stderr, "daemon: vmm worker died:", d.runner.Err())
		return 1
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

func closedWhenNetworkWorkerExits(network *Network) <-chan struct{} {
	if network == nil || network.Worker == nil {
		return nil
	}
	return network.Worker.Done()
}

func closedWhenVMMWorkerExits(runner vmmworker.Runner) <-chan struct{} {
	if runner == nil {
		return nil
	}
	return runner.Done()
}

func (d *daemonRuntime) gracefulStop(reason string) int {
	fmt.Println("daemon:", reason, "— shutting down")
	_ = d.control.Close() // no new broker sessions

	// Process exit is a power cut for the guest. Flush while the RPC
	// connection is still held: guest filesystem first (bounded because it
	// may be wedged), then host-side devices.
	if err := client.SyncGuest(d.rpc, 5*time.Second); err != nil {
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
func (d *daemonRuntime) closeShutdownDevices() error {
	var networkErr error
	if d.network != nil && (d.network.Split || d.network.Sock != "") {
		networkErr = d.network.CloseBackend()
	}
	return errors.Join(networkErr, d.closeVMDevices())
}

func (d *daemonRuntime) closeVMDevices() error {
	if d.runner != nil {
		err := d.runner.Close()
		d.runner = nil // explicit close owns error reporting; defer must not repeat it.
		return err
	}
	if d.machine != nil {
		return d.machine.Close()
	}
	return nil
}
