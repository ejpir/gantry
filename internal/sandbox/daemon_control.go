package sandbox

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ejpir/gantry/internal/client"
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
	if err := secureLocalEndpoint(path); err != nil {
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
		cfg:        d.cfg,
		dir:        d.dir,
		rpc:        d.rpc,
		streamSock: filepath.Join(d.dir, "listen-1026.sock"),
		streamDial: streamDial,
		secrets:    d.secrets,
		store:      d.store,
		shares:     d.shares,
		ports:      d.ports,
		netPolicy:  NewNetworkPolicyManager(d.store, d.network.Backend, d.network.Policy),
		capture:    packetCaptureBackendFor(d.network, d.runner),
		sessions:   map[string]chan struct{}{},
		sessionCtl: map[string]net.Conn{},
		shutdown:   d.shutdown,
	}
	d.broker.oauth = newOAuthBridge(d.broker)
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

func closedWhenVMMWorkerExits(runner vmmRunner) <-chan struct{} {
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
	client.SyncGuestDial(d.rpc, d.broker.streamDial, d.broker.streamSock, "sb", 5*time.Second)
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
