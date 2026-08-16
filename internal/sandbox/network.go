package sandbox

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"

	"github.com/ejpir/gantry/internal/netpol"
	"github.com/ejpir/gantry/internal/networkworker"
	"github.com/ejpir/gantry/internal/vnet"
	"github.com/ejpir/gantry/internal/workerconf"
)

// Network is a resolved network backend plus egress policy for one run.
type Network struct {
	Sock    string // external gvproxy endpoint ("" when embedded)
	Conn    net.Conn
	Stack   *vnet.Stack // nil for the gvproxy backend
	Policy  *netpol.Policy
	Traffic *netpol.TrafficRecorder
	// Backend is the control surface for live policy/port mutations:
	// the embedded stack in-process (monolithic) or the split network
	// worker over RPC. Nil for the gvproxy backend and -net=false.
	Backend NetworkBackend
	// Split reports that networking runs in a separate _net-worker
	// process: Conn is the supervisor end of the framed data channel.
	// Policy stays as the supervisor's authoritative copy for display
	// and rollback (Opts does NOT attach it to the device — enforcement
	// is the worker's). Traffic is the supervisor-owned lifetime recorder;
	// the worker keeps only per-boot in-memory counters.
	Split  bool
	Worker *netWorker
	// Confinement is the network worker's verified bootstrap report. It is
	// distinct from the VMM worker report because the network role retains
	// tightly scoped socket creation authority.
	Confinement *workerconf.Report
	// Degraded lists isolation properties requested but not established
	// (auto mode only; required fails instead). Surfaced by the daemon.
	Degraded    []string
	close       func() error
	backendOnce sync.Once
	backendErr  error
	trafficOnce sync.Once
}

// CloseBackend releases the netstack / gvproxy process / connection while
// leaving the traffic recorder alive until device shutdown completes.
func (n *Network) CloseBackend() error {
	if n == nil {
		return nil
	}
	n.backendOnce.Do(func() {
		if n.close != nil {
			n.backendErr = n.close()
		}
	})
	return n.backendErr
}

// Close releases the backend and publishes the final traffic snapshot.
func (n *Network) Close() {
	if n == nil {
		return
	}
	_ = n.CloseBackend()
	n.trafficOnce.Do(func() {
		if n.Traffic != nil {
			n.Traffic.Close()
		}
	})
}

// NetMarker is the "networking enabled" marker DefaultCmdline consumes.
func NetMarker(sock string, conn net.Conn) string {
	if sock != "" || conn != nil {
		return "enabled"
	}
	return ""
}

// StartNetwork builds the egress policy and brings up the configured
// backend. workdir holds the gvproxy socket/log when an external gvproxy
// is used. A nil *Network (with nil error) means -net=false.
func (c RunConfig) StartNetwork(workdir string) (*Network, error) {
	if err := validateProxyConfig(c); err != nil {
		return nil, err
	}
	if (c.NetPol != "" || c.AllowLN) && c.GVProxy != "" {
		return nil, fmt.Errorf("-net-policy/-allow-local-net require the embedded netstack (drop -gvproxy)")
	}
	var policy *netpol.Policy
	if c.NetPol != "" {
		var err error
		policy, err = netpol.Load(c.NetPol)
		if err != nil {
			return nil, err
		}
	}
	if c.AllowLN {
		if policy == nil {
			policy = netpol.DefaultPolicy()
		}
		policy.AllowLocal = true
	}
	if policy == nil && c.Net {
		policy = netpol.DefaultPolicy() // internet yes, local net no
	}
	var err error
	policy, err = c.applyProxyPolicy(policy)
	if err != nil {
		return nil, err
	}
	if !c.Net {
		return &Network{Policy: policy}, nil
	}

	n := &Network{Policy: policy}
	if c.GVProxy != "" {
		gv, sock, err := StartGVProxy(c.GVProxy, workdir)
		if err != nil {
			return nil, err
		}
		n.Sock = sock
		n.close = func() error {
			_ = gv.Process.Kill()
			_ = gv.Wait()
			return nil
		}
		n.Traffic = netpol.NewTrafficRecorder(filepath.Join(workdir, netpol.TrafficFileName))
		return n, nil
	}
	if c.splitNetWorkerWanted() && os.Getenv("GANTRY_NET_PCAP") != "" {
		err := fmt.Errorf("split network worker does not support GANTRY_NET_PCAP without host-path authority")
		if c.ProcessIsolation == "required" {
			return nil, fmt.Errorf("process isolation required but unavailable: %w", err)
		}
		n.Degraded = append(n.Degraded, "network-worker: "+err.Error())
	} else if c.splitNetWorkerWanted() {
		mode := effectiveProcessIsolation(c.ProcessIsolation)
		confRoot := filepath.Join(workdir, "networkroot")
		err := os.MkdirAll(confRoot, 0o700)
		if err == nil {
			err = os.Chmod(confRoot, 0o700)
		}
		var worker *netWorker
		var conn net.Conn
		if err == nil {
			worker, conn, err = startNetWorker(networkworker.Config{
				GuestMAC:    net.HardwareAddr(guestNetMAC[:]).String(),
				Forwards:    portForwards(c.Ports),
				Policy:      mustMarshalPolicy(policy),
				Debug:       netWorkerTrafficDebug(),
				Confinement: mode,
				ConfRoot:    confRoot,
			}, workdir)
		}
		if err == nil {
			traffic := netpol.NewTrafficRecorder(filepath.Join(workdir, netpol.TrafficFileName))
			worker.startTrafficSync(traffic)
			n.Conn = conn
			n.Backend = worker
			n.Split = true
			n.Worker = worker
			n.Traffic = traffic
			n.Confinement = worker.ConfinementReport()
			// The worker owns enforcement and the stack. The supervisor owns
			// durable traffic state and pulls cumulative in-memory snapshots.
			n.close = worker.Close
			return n, nil
		}
		if c.ProcessIsolation == "required" {
			return nil, fmt.Errorf("process isolation required but unavailable: %w", err)
		}
		n.Degraded = append(n.Degraded, "network-worker: "+err.Error())
		// auto: fall through to the monolithic embedded stack
	}

	stack, err := vnet.Start(guestNetMAC, portForwards(c.Ports))
	if err != nil {
		return nil, err
	}
	var conn net.Conn
	if vmmWorkerPlatform && c.ProcessIsolation != "off" {
		// The VMM may move to a _vmm-worker: the net data channel must
		// survive the crossing (net.Pipe cannot). A socketpair works
		// identically in-process if the split degrades.
		sup, dev, err := crossProcNetConn()
		if err == nil {
			// Attach owns sup (closed when the stack stops); dev stays
			// ours and crosses into the VMM worker on split.
			if _, err := stack.Attach(dev, sup); err != nil {
				_ = dev.Close()
				_ = sup.Close()
				stack.Close()
				return nil, err
			}
			conn = dev
		}
	}
	if conn == nil {
		conn, err = stack.Dial()
		if err != nil {
			stack.Close()
			return nil, err
		}
	}
	n.Conn = conn
	n.Stack = stack
	n.Backend = newLocalBackend(stack, policy)
	n.close = func() error {
		err := conn.Close()
		stack.Close()
		if errors.Is(err, net.ErrClosed) {
			return nil
		}
		return err
	}
	n.Traffic = netpol.NewTrafficRecorder(filepath.Join(workdir, netpol.TrafficFileName))
	return n, nil
}

// splitNetWorkerWanted reports whether StartNetwork should attempt the
// split network worker: networking on, embedded stack (gvproxy stays a
// monolithic compatibility path), and isolation not explicitly off.
func (c RunConfig) splitNetWorkerWanted() bool {
	return c.Net && c.GVProxy == "" && c.ProcessIsolation != "off"
}

// mustMarshalPolicy serializes the boot policy for the worker handshake.
// StartNetwork guarantees a non-nil, parsed policy on the split path, so
// a marshal failure is a bug, not user error.
func mustMarshalPolicy(policy *netpol.Policy) []byte {
	raw, err := netpol.Marshal(policy)
	if err != nil {
		panic(err)
	}
	return raw
}

// portForwards translates canonical publish specs into the netstack's
// static forward map ("udp:" key prefix for UDP, per gvisor-tap-vsock).
func portForwards(specs []string) map[string]string {
	if len(specs) == 0 {
		return nil
	}
	forwards := make(map[string]string, len(specs))
	for _, spec := range specs {
		m, err := ParsePortSpec(spec)
		if err != nil {
			continue // Resolve validated every spec
		}
		local := m.Local()
		if m.Proto == "udp" {
			local = "udp:" + local
		}
		forwards[local] = m.Remote()
	}
	return forwards
}
