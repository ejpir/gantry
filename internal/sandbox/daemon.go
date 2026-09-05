package sandbox

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/ejpir/gantry/internal/sandbox/boundedlog"
	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/control"
	mcpworkersup "github.com/ejpir/gantry/internal/sandbox/mcpworker"
	"github.com/ejpir/gantry/internal/sandbox/vmmworker"
	"github.com/ejpir/gantry/internal/secret"
	"github.com/ejpir/gantry/internal/vmm"

	"github.com/containerd/ttrpc"
)

// daemonRuntime owns the resources of one daemon process. Fields are ordered
// by acquisition; close releases them in reverse order. The monolithic
// machine is deliberately excluded from close: an unexpected daemon exit is a
// power cut, while gracefulStop explicitly flushes the guest and its devices.
type daemonRuntime struct {
	name        string
	readySocket string
	dir         string

	started    time.Time
	bootTiming bool

	cfg         config.RunConfig
	secretStore *secret.Store
	// audit is the daemon-wide security-event trail (secret source errors,
	// credhelper decisions, custody events); the broker serves it over
	// audit.tail once the control socket is up.
	audit   *auditRing
	store   *config.ConfigStore
	lock    *os.File
	console *os.File
	// consoleLog owns the regular console.log file and drains console through
	// a bounded stream. console is only its write-side capability.
	consoleLog *boundedlog.Pipe
	network    *Network
	shares     *control.ShareManager
	// networkTransactions spans each live policy/port mutation through its
	// persistence and rollback phase. Both control managers sharing the network
	// backend must use this same coordinator.
	networkTransactions *control.NetworkTransactionCoordinator
	// Guest-tool delivery uses RPC and shares. The lifecycle gate prevents new
	// deliveries once teardown starts and lets close cancel/join every owner
	// before either dependency is released; guestToolsMu serializes retries.
	guestToolsMu       sync.Mutex
	guestToolsLifeMu   sync.Mutex
	guestToolsCtx      context.Context
	guestToolsCancel   context.CancelFunc
	guestToolsStopping bool
	guestToolsWG       sync.WaitGroup
	ports              *control.PortManager
	runner             vmmworker.Runner
	machine            *vmm.Machine
	rpc                *ttrpc.Client
	control            net.Listener
	broker             *broker
	sshMu              sync.Mutex
	sshListener        net.Listener
	sshCancel          func()
	mcpListener        net.Listener
	mcpWorker          *mcpworkersup.Worker

	guestErr <-chan error
	signals  chan os.Signal
	shutdown chan struct{}

	// postReady, when non-nil, replaces supervise() after publishReady:
	// hidden spike commands (docs/kubernetes-runtimeclass.md, Phase K0) run
	// their scenario against the fully booted guest instead of serving
	// ctl.sock sessions.
	postReady func(d *daemonRuntime) int
}

func CmdDaemon(name, readySocket string) int {
	d := &daemonRuntime{
		name:        name,
		readySocket: readySocket,
		started:     time.Now(),
		bootTiming:  os.Getenv("GANTRY_BOOT_TIMING") != "",
	}
	return d.run()
}

func (d *daemonRuntime) run() int {
	d.bootLog("daemon started")
	defer d.close()

	if err := d.load(); err != nil {
		return daemonFailure(err)
	}
	if err := d.startHostServices(); err != nil {
		return daemonFailure(err)
	}
	if err := d.prepareGuest(); err != nil {
		return daemonFailure(err)
	}
	if err := d.connectGuest(); err != nil {
		return daemonFailure(err)
	}
	if err := d.startControl(); err != nil {
		return daemonFailure(err)
	}
	// MCP, bound secrets, and OAuth custody require the workload helper before
	// readiness. SSH helper delivery remains asynchronous even when it targets a
	// second IDE root; an early connection waits on that root's own completion.
	plan := planGuestToolsDelivery(d.cfg)
	workloadTarget := guestToolsTarget{label: "workload"}
	ideTarget := guestToolsTarget{ide: true, label: "IDE"}
	if plan.workloadRequired {
		if !d.ensureGuestToolsTargetsAndSignal(d.cfg, []guestToolsTarget{workloadTarget}) {
			return daemonFailure(fmt.Errorf("required guest helper delivery failed"))
		}
	} else if plan.workloadAsync {
		d.startAsyncGuestToolsDelivery(d.cfg, []guestToolsTarget{workloadTarget})
	}
	if plan.ideAsync {
		d.startAsyncGuestToolsDelivery(d.cfg, []guestToolsTarget{ideTarget})
	}
	// Readiness means both the guest RPC and the local authenticated control
	// broker can accept work. Publishing it from connectGuest left a window in
	// which `gantry start` returned successfully before ctl.sock existed, so an
	// immediate `gantry exec` could race startup and produce no guest output.
	if err := d.publishReady(); err != nil {
		return daemonFailure(err)
	}
	if d.postReady != nil {
		return d.postReady(d)
	}
	return d.supervise()
}

func daemonFailure(err error) int {
	fmt.Fprintln(os.Stderr, "daemon:", err)
	return 1
}

func (d *daemonRuntime) bootLog(phase string) {
	if !d.bootTiming {
		return
	}
	fmt.Fprintf(os.Stderr, "boot-timing: %-36s %9.3f ms\n", phase, float64(time.Since(d.started))/float64(time.Millisecond))
}

func (d *daemonRuntime) close() {
	// Delivery owns RPC sessions and temporary shares. Cancel and join it
	// before closing any of those resources. gracefulStop may already have
	// done this; stopGuestToolsDelivery is deliberately idempotent.
	d.stopGuestToolsDelivery()
	d.stopSSHGateway()
	if d.mcpListener != nil {
		_ = d.mcpListener.Close()
	}
	if d.mcpWorker != nil {
		if err := d.mcpWorker.Close(); err != nil {
			fmt.Fprintln(os.Stderr, "daemon: MCP worker:", err)
		}
	}
	if d.control != nil {
		_ = d.control.Close()
	}
	if d.signals != nil {
		signal.Stop(d.signals)
	}
	if d.rpc != nil {
		_ = d.rpc.Close()
	}
	if d.runner != nil {
		_ = d.runner.Close()
	}
	if d.shares != nil {
		_ = d.shares.Close()
	}
	if d.network != nil {
		d.network.Close()
	}
	if d.console != nil {
		_ = d.console.Close()
	}
	if d.consoleLog != nil {
		if err := d.consoleLog.Close(); err != nil {
			fmt.Fprintln(os.Stderr, "daemon: console log broker:", err)
		}
	}
	if d.lock != nil {
		_ = d.lock.Close()
	}
}
