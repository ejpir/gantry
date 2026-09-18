package sandbox

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/ejpir/gantry/internal/policy"
	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/controlplane"
	"github.com/ejpir/gantry/internal/sandbox/guestplane"
	sandboxsupervisor "github.com/ejpir/gantry/internal/sandbox/supervisor"
	"github.com/ejpir/gantry/internal/secret"
)

// daemonSupervisor is the supervisor for one daemon process. It owns the phase
// machine and four explicit resource owners. Acquisition proceeds host,
// guest, control, then background borrowers; close releases them in the exact
// reverse order.
type daemonSupervisor struct {
	name        string
	readySocket string
	dir         string

	started    time.Time
	bootTiming bool
	lifecycle  sandboxsupervisor.Lifecycle

	host       hostPlane
	guest      guestplane.Plane
	control    controlplane.Plane[*broker]
	background sandboxsupervisor.BackgroundGroup

	cfg         config.RunConfig
	secretStore *secret.Store
	governance  *policy.Controller
	// policyUpdateMu serializes live organization-policy generations inside the
	// daemon. policyChanged wakes supervise so expiry follows the active engine.
	policyUpdateMu sync.Mutex
	policyChanged  chan struct{}
	// Guest-tool delivery borrows control, guest, and host resources. Its
	// background group is therefore closed before any of those owners.
	guestToolsMu sync.Mutex

	// postReady, when non-nil, replaces supervise() after publishReady:
	// hidden spike commands (docs/kubernetes-runtimeclass.md, Phase K0) run
	// their scenario against the fully booted guest instead of serving
	// ctl.sock sessions.
	postReady func(d *daemonSupervisor) int
}

func CmdDaemon(name, readySocket string) int {
	d := &daemonSupervisor{
		name:        name,
		readySocket: readySocket,
		started:     time.Now(),
		bootTiming:  os.Getenv("GANTRY_BOOT_TIMING") != "",
	}
	return d.run()
}

func (d *daemonSupervisor) run() (exitCode int) {
	d.bootLog("daemon started")
	defer func() {
		// Every exit, including a partial boot failure, crosses the same teardown
		// phase. Publish the terminal outcome only after daemonSupervisor.close has
		// completed its process-level teardown policy.
		d.lifecycle.BeginStop()
		d.close()
		if err := d.lifecycle.Finish(exitCode != 0); err != nil {
			fmt.Fprintln(os.Stderr, "daemon: lifecycle:", err)
			exitCode = 1
		}
	}()

	if err := d.load(); err != nil {
		return daemonFailure(err)
	}
	if err := d.lifecycle.Advance(sandboxsupervisor.Loaded); err != nil {
		return daemonFailure(err)
	}
	if err := d.startHostServices(); err != nil {
		return daemonFailure(err)
	}
	if err := d.lifecycle.Advance(sandboxsupervisor.HostReady); err != nil {
		return daemonFailure(err)
	}
	if err := d.prepareGuest(); err != nil {
		return daemonFailure(err)
	}
	if err := d.lifecycle.Advance(sandboxsupervisor.GuestPrepared); err != nil {
		return daemonFailure(err)
	}
	if err := d.connectGuest(); err != nil {
		return daemonFailure(err)
	}
	if err := d.lifecycle.Advance(sandboxsupervisor.GuestConnected); err != nil {
		return daemonFailure(err)
	}
	if err := d.startControl(); err != nil {
		return daemonFailure(err)
	}
	if err := d.lifecycle.Advance(sandboxsupervisor.ControlReady); err != nil {
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
	if err := d.startOAuthListenerWatch(); err != nil {
		return daemonFailure(err)
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

func (d *daemonSupervisor) bootLog(phase string) {
	if !d.bootTiming {
		return
	}
	fmt.Fprintf(os.Stderr, "boot-timing: %-36s %9.3f ms\n", phase, float64(time.Since(d.started))/float64(time.Millisecond))
}

func (d *daemonSupervisor) close() {
	// Background deliveries were acquired last and borrow all three planes.
	// Every owner is idempotent because graceful shutdown may have released a
	// subset of its resources before this process-level unwind.
	d.background.Close()
	if err := d.control.Close(); err != nil {
		fmt.Fprintln(os.Stderr, "daemon: control plane:", err)
	}
	if err := d.guest.Close(); err != nil {
		fmt.Fprintln(os.Stderr, "daemon: guest plane:", err)
	}
	if err := d.host.Close(); err != nil {
		fmt.Fprintln(os.Stderr, "daemon: host plane:", err)
	}
}
