package sandbox

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/ejpir/gantry/internal/client"
	"github.com/ejpir/gantry/internal/mcpspec"
	"github.com/ejpir/gantry/internal/netpol"
	"github.com/ejpir/gantry/internal/packetcapture"
	"github.com/ejpir/gantry/internal/policy"
	"github.com/ejpir/gantry/internal/sandbox/boundedlog"
	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/control"
	"github.com/ejpir/gantry/internal/sandbox/vmmworker"
	"github.com/ejpir/gantry/internal/sharefs"
	"github.com/ejpir/gantry/internal/shares"
	"github.com/ejpir/gantry/internal/vmm"
	"github.com/ejpir/gantry/internal/workerconf"

	"github.com/containerd/ttrpc"
)

// configStoreBorrow is the non-owning configuration capability shared with
// the broker and live reconcilers. ConfigStore has no lifetime operation.
type configStoreBorrow interface {
	Snapshot() config.RunConfig
	BeginConfiguration(config.SandboxUpdate) (*config.ConfigurationTransaction, error)
	SetOrganizationPolicy(*policy.Config) error
	SetSecretName(string, bool) error
	SetMCPRemote(string, bool) (mcpspec.Remote, error)
	RemoveMCPRemote(string) error
	SetMCPFilesystem(string, string) error
	SetResources(uint, int, string) error
}

// shareManagerBorrow exposes live share operations but not Close. Only
// hostPlane may release the share manager.
type shareManagerBorrow interface {
	Hub() sharefs.BorrowedHub
	Publish() error
	WithGuestToolsShare(context.Context, []byte, func(shares.Entry) error) error
	ConfigureRestart(string, bool) (shares.Spec, error)
	Add(string, bool, bool) (shares.Entry, error)
	Remove(string, bool, bool) (shares.Entry, error)
	Generation() uint64
	Entries() []shares.Entry
	SetPolicyBlocked(bool)
	ReconcileOrganizationPolicy(*policy.Engine) error
	Failed() bool
}

type networkWorkerBorrow interface {
	Done() <-chan struct{}
	Err() error
}

type networkWorkerView struct{ worker networkWorkerBorrow }

func (v networkWorkerView) Done() <-chan struct{} { return v.worker.Done() }
func (v networkWorkerView) Err() error            { return v.worker.Err() }

// networkBorrow contains guest/control observations but no backend shutdown.
// CloseBackend and Close remain methods only of hostPlane's concrete resource.
type networkBorrow interface {
	vmmAttachment() vmmworker.NetAttachment
	captureBackend(packetCaptureBackend) packetCaptureBackend
	workerBorrow() networkWorkerBorrow
}

type networkView struct{ network *Network }

func (v networkView) vmmAttachment() vmmworker.NetAttachment { return v.network.vmmAttachment() }
func (v networkView) captureBackend(runnerCapture packetCaptureBackend) packetCaptureBackend {
	n := v.network
	if n.Worker != nil {
		return guestPacketCaptureView{capture: n.Worker}
	}
	if runnerCapture != nil {
		return runnerCapture
	}
	if n.Traffic != nil {
		return guestPacketCaptureView{capture: n.Traffic}
	}
	return nil
}
func (v networkView) workerBorrow() networkWorkerBorrow {
	if v.network.Worker == nil {
		return nil
	}
	return networkWorkerView{worker: v.network.Worker}
}

// portManagerBorrow deliberately excludes resource release; PortManager is a
// host-plane service without an independent Close operation.
type portManagerBorrow interface {
	Publish(string, bool) (control.PortEntry, error)
	Unpublish(string, bool) (control.PortEntry, error)
	List() ([]control.PortEntry, error)
}

// guestRunnerBorrow is all supervisor/control code may use from a split VMM.
// Close and Wait remain private to guestPlane.
type guestRunnerBorrow interface {
	RequestHotMemory() error
	Done() <-chan struct{}
	Err() error
	DialStream(uint32) (net.Conn, error)
}

// guestRPCBorrow is a high-level guest capability. It intentionally does not
// reveal the ttrpc client or its Close method.
type guestRPCBorrow interface {
	Session(client.SessionOptions, io.Reader, io.Writer) error
}

type shareManagerView struct{ manager *control.ShareManager }

func (v shareManagerView) Hub() sharefs.BorrowedHub { return sharefs.Borrow(v.manager.Hub()) }
func (v shareManagerView) Publish() error           { return v.manager.Publish() }
func (v shareManagerView) WithGuestToolsShare(ctx context.Context, data []byte, use func(shares.Entry) error) error {
	return v.manager.WithGuestToolsShare(ctx, data, use)
}
func (v shareManagerView) ConfigureRestart(spec string, replace bool) (shares.Spec, error) {
	return v.manager.ConfigureRestart(spec, replace)
}
func (v shareManagerView) Add(spec string, persistent, replace bool) (shares.Entry, error) {
	return v.manager.Add(spec, persistent, replace)
}
func (v shareManagerView) Remove(tag string, persistent, force bool) (shares.Entry, error) {
	return v.manager.Remove(tag, persistent, force)
}
func (v shareManagerView) Generation() uint64            { return v.manager.Generation() }
func (v shareManagerView) Entries() []shares.Entry       { return v.manager.Entries() }
func (v shareManagerView) SetPolicyBlocked(blocked bool) { v.manager.SetPolicyBlocked(blocked) }
func (v shareManagerView) ReconcileOrganizationPolicy(engine *policy.Engine) error {
	return v.manager.ReconcileOrganizationPolicy(engine)
}
func (v shareManagerView) Failed() bool { return v.manager.Failed() }

type guestRunnerView struct{ runner vmmworker.Runner }

func (v guestRunnerView) RequestHotMemory() error { return v.runner.RequestHotMemory() }
func (v guestRunnerView) Done() <-chan struct{}   { return v.runner.Done() }
func (v guestRunnerView) Err() error              { return v.runner.Err() }
func (v guestRunnerView) DialStream(port uint32) (net.Conn, error) {
	return v.runner.DialStream(port)
}

type guestPolicyPusherView struct{ pusher control.VMMPolicyPusher }

func (v guestPolicyPusherView) SetPolicy(policy *netpol.Policy) error {
	return v.pusher.SetPolicy(policy)
}

type guestPacketCaptureView struct{ capture packetCaptureBackend }

func (v guestPacketCaptureView) Capture(request packetcapture.Request) (packetcapture.Snapshot, error) {
	return v.capture.Capture(request)
}

type guestRPCClient struct{ client *ttrpc.Client }

func (c guestRPCClient) Session(options client.SessionOptions, stdin io.Reader, stdout io.Writer) error {
	return client.Session(c.client, options, stdin, stdout)
}

// hostPlane owns every host resource acquired before the guest starts.
type hostPlane struct {
	closeOnce sync.Once
	closeErr  error

	lock       *os.File
	store      *config.ConfigStore
	audit      *auditRing
	console    *os.File
	consoleLog *boundedlog.Pipe
	network    *Network
	shares     *control.ShareManager
	ports      *control.PortManager
	networkTx  *control.NetworkTransactionCoordinator
}

func (h *hostPlane) config() configStoreBorrow {
	if h.store == nil {
		return nil
	}
	return h.store
}
func (h *hostPlane) networkBorrow() networkBorrow {
	if h.network == nil {
		return nil
	}
	return networkView{network: h.network}
}

func (h *hostPlane) shareBorrow() shareManagerBorrow {
	if h.shares == nil {
		return nil
	}
	return shareManagerView{manager: h.shares}
}
func (h *hostPlane) portBorrow() portManagerBorrow {
	if h.ports == nil {
		return nil
	}
	return h.ports
}

func (h *hostPlane) vmmOptions(cfg config.RunConfig, vsockFwd string, envExtra bool) (vmm.Opts, error) {
	return vmmOpts(cfg, h.network, vsockFwd, envExtra)
}

func (h *hostPlane) closeShutdownNetwork() error {
	if h.network == nil || (!h.network.Split && h.network.Sock == "") {
		return nil
	}
	return h.network.CloseBackend()
}

func (h *hostPlane) close() error {
	h.closeOnce.Do(func() {
		var result error
		if h.shares != nil {
			result = errors.Join(result, h.shares.Close())
		}
		if h.network != nil {
			h.network.Close()
		}
		if h.console != nil {
			result = errors.Join(result, h.console.Close())
		}
		if h.consoleLog != nil {
			result = errors.Join(result, h.consoleLog.Close())
		}
		if h.lock != nil {
			result = errors.Join(result, h.lock.Close())
		}
		h.closeErr = result
	})
	return h.closeErr
}

// guestPlane is the only owner allowed to close the VMM execution handle and
// guest RPC client. The exit channel is published after its waiter has been
// admitted to workers.
type guestPlane struct {
	mu sync.RWMutex

	runner  vmmworker.Runner
	machine *vmm.Machine
	rpc     *ttrpc.Client
	exit    <-chan error

	workers          backgroundGroup
	devicesCloseOnce sync.Once
	devicesCloseErr  error
	closeOnce        sync.Once
	closeErr         error
}

func (g *guestPlane) setRunner(runner vmmworker.Runner) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.runner = runner
}
func (g *guestPlane) setMachine(machine *vmm.Machine) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.machine = machine
}
func (g *guestPlane) setRPC(rpc *ttrpc.Client) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.rpc = rpc
}

func (g *guestPlane) runnerBorrow() guestRunnerBorrow {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.runner == nil {
		return nil
	}
	return guestRunnerView{runner: g.runner}
}

func (g *guestPlane) policyPusherBorrow() control.VMMPolicyPusher {
	g.mu.RLock()
	defer g.mu.RUnlock()
	pusher, ok := g.runner.(control.VMMPolicyPusher)
	if !ok {
		return nil
	}
	return guestPolicyPusherView{pusher: pusher}
}

func (g *guestPlane) packetCaptureBorrow() packetCaptureBackend {
	g.mu.RLock()
	defer g.mu.RUnlock()
	capture, ok := g.runner.(packetCaptureBackend)
	if !ok {
		return nil
	}
	return guestPacketCaptureView{capture: capture}
}

func (g *guestPlane) confinementReport() (*workerconf.Report, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	reporter, ok := g.runner.(interface{ ConfinementReport() workerconf.Report })
	if !ok {
		return nil, false
	}
	report := reporter.ConfinementReport()
	return &report, true
}

func (g *guestPlane) rpcBorrow() guestRPCBorrow {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.rpc == nil {
		return nil
	}
	return guestRPCClient{client: g.rpc}
}

func (g *guestPlane) start() <-chan error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.exit != nil {
		return g.exit
	}
	exited := make(chan error, 1)
	runner, machine := g.runner, g.machine
	if !g.workers.start(func(context.Context) {
		if runner != nil {
			exited <- runner.Wait()
			return
		}
		exited <- vmm.Run(machine)
	}) {
		close(exited)
	}
	g.exit = exited
	return exited
}

func (g *guestPlane) exited() <-chan error {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.exit
}

func (g *guestPlane) sync(timeout time.Duration) error {
	g.mu.RLock()
	rpc := g.rpc
	g.mu.RUnlock()
	if rpc == nil {
		return fmt.Errorf("guest RPC unavailable")
	}
	return client.SyncGuest(rpc, timeout)
}

func (g *guestPlane) multiContainerSpike(options client.SpikeOptions) error {
	g.mu.RLock()
	rpc := g.rpc
	g.mu.RUnlock()
	if rpc == nil {
		return fmt.Errorf("guest RPC unavailable")
	}
	return client.MultiContainerSpike(rpc, options)
}

func (g *guestPlane) rootfsSpike(options client.RootfsSpikeOptions) (*client.RootfsSpikeResult, error) {
	g.mu.RLock()
	rpc := g.rpc
	g.mu.RUnlock()
	if rpc == nil {
		return nil, fmt.Errorf("guest RPC unavailable")
	}
	return client.RootfsSpike(rpc, options)
}

func (g *guestPlane) requestHotMemory() error {
	g.mu.RLock()
	runner, machine := g.runner, g.machine
	g.mu.RUnlock()
	if runner != nil {
		return runner.RequestHotMemory()
	}
	if machine != nil {
		return machine.RequestHotMemory()
	}
	return nil
}

func (g *guestPlane) closeDevices() error {
	g.devicesCloseOnce.Do(func() {
		g.mu.RLock()
		runner, machine := g.runner, g.machine
		g.mu.RUnlock()
		if runner != nil {
			g.devicesCloseErr = runner.Close()
		} else if machine != nil {
			g.devicesCloseErr = machine.Close()
		}
	})
	return g.devicesCloseErr
}

func (g *guestPlane) close() error {
	g.closeOnce.Do(func() {
		g.mu.RLock()
		rpc := g.rpc
		g.mu.RUnlock()
		var result error
		if rpc != nil {
			result = errors.Join(result, rpc.Close())
		}
		result = errors.Join(result, g.closeDevices())
		g.workers.close()
		g.closeErr = result
	})
	return g.closeErr
}

// controlPlane owns every host endpoint which can admit new guest/control
// work. Its background groups are joined before the guest and host planes are
// released by the supervisor.
type controlPlane struct {
	closeOnce sync.Once
	closeErr  error

	listener     net.Listener
	credListener net.Listener
	broker       *broker
	ssh          sshGatewayOwner
	sshCleanup   func()
	mcp          mcpGatewayOwner
	oauth        backgroundGroup
	servers      backgroundGroup
	signals      chan os.Signal
	shutdown     chan struct{}
}

func (c *controlPlane) closeAdmission() {
	if c.listener != nil {
		_ = c.listener.Close()
	}
}

func (c *controlPlane) stopOAuth() { c.oauth.close() }

func (c *controlPlane) close() error {
	c.closeOnce.Do(func() {
		c.stopOAuth()
		c.closeAdmission()
		c.ssh.stop()
		if c.sshCleanup != nil {
			c.sshCleanup()
		}
		var result error
		result = errors.Join(result, c.mcp.close())
		if c.credListener != nil {
			result = errors.Join(result, c.credListener.Close())
		}
		if c.signals != nil {
			signal.Stop(c.signals)
		}
		c.servers.close()
		c.closeErr = result
	})
	return c.closeErr
}

// Compile-time checks keep owning implementations assignable to their
// non-owning capabilities.
var (
	_ guestRunnerBorrow   = guestRunnerView{}
	_ networkBorrow       = networkView{}
	_ networkWorkerBorrow = networkWorkerView{}
	_ shareManagerBorrow  = shareManagerView{}
)
