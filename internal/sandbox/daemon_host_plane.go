package sandbox

import (
	"context"
	"os"

	"github.com/ejpir/gantry/internal/mcpspec"
	"github.com/ejpir/gantry/internal/netpol"
	"github.com/ejpir/gantry/internal/packetcapture"
	"github.com/ejpir/gantry/internal/policy"
	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/control"
	"github.com/ejpir/gantry/internal/sandbox/hostplane"
	"github.com/ejpir/gantry/internal/sandbox/vmmworker"
	"github.com/ejpir/gantry/internal/sharefs"
	"github.com/ejpir/gantry/internal/shares"
	"github.com/ejpir/gantry/internal/vmm"
	"github.com/ejpir/gantry/internal/workerconf"
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
	VMMAttachment() vmmworker.NetAttachment
	CaptureBackend(packetCaptureBackend) packetCaptureBackend
	WorkerBorrow() networkWorkerBorrow
	Policy() *netpol.Policy
	Backend() control.NetworkBackend
	SetBackend(control.NetworkBackend)
	Degraded() []string
	Split() bool
	WorkerError() error
	Confinement() *workerconf.Report
	VMMOptions(config.RunConfig, string, bool) (vmm.Opts, error)
}

type networkView struct{ network *Network }

func (v networkView) VMMAttachment() vmmworker.NetAttachment { return v.network.vmmAttachment() }
func (v networkView) CaptureBackend(runnerCapture packetCaptureBackend) packetCaptureBackend {
	n := v.network
	if n.Worker != nil {
		return packetCaptureView{capture: n.Worker}
	}
	if runnerCapture != nil {
		return runnerCapture
	}
	if n.Traffic != nil {
		return packetCaptureView{capture: n.Traffic}
	}
	return nil
}
func (v networkView) WorkerBorrow() networkWorkerBorrow {
	if v.network.Worker == nil {
		return nil
	}
	return networkWorkerView{worker: v.network.Worker}
}
func (v networkView) Policy() *netpol.Policy                    { return v.network.Policy }
func (v networkView) Backend() control.NetworkBackend           { return v.network.Backend }
func (v networkView) SetBackend(backend control.NetworkBackend) { v.network.Backend = backend }
func (v networkView) Degraded() []string                        { return v.network.Degraded }
func (v networkView) Split() bool                               { return v.network.Split }
func (v networkView) Confinement() *workerconf.Report           { return v.network.Confinement }
func (v networkView) VMMOptions(cfg config.RunConfig, vsock string, extra bool) (vmm.Opts, error) {
	return vmmOpts(cfg, v.network, vsock, extra)
}
func (v networkView) WorkerError() error {
	if v.network.Worker == nil {
		return nil
	}
	return v.network.Worker.Err()
}

// portManagerBorrow deliberately excludes resource release; PortManager is a
// host-plane service without an independent Close operation.
type portManagerBorrow interface {
	Publish(string, bool) (control.PortEntry, error)
	Unpublish(string, bool) (control.PortEntry, error)
	List() ([]control.PortEntry, error)
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

type packetCaptureView struct{ capture packetCaptureBackend }

func (v packetCaptureView) Capture(request packetcapture.Request) (packetcapture.Snapshot, error) {
	return v.capture.Capture(request)
}

// hostPlane binds daemon-specific borrowed capabilities to the generic owner.
type hostPlane = hostplane.Plane[*config.ConfigStore, *auditRing, networkBorrow, shareManagerBorrow, portManagerBorrow, *control.NetworkTransactionCoordinator, *os.File]

// Compile-time checks keep owning implementations assignable to their
// non-owning capabilities.
var (
	_ networkBorrow       = networkView{}
	_ networkWorkerBorrow = networkWorkerView{}
	_ shareManagerBorrow  = shareManagerView{}
)
