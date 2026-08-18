//go:build linux || darwin

package vmmworker

// Split-VMM launch (unix): the descriptor table, SCM_RIGHTS channel, and
// re-exec all exist here. See docs/vmm-network-isolation.md phase 2.

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/ejpir/gantry/internal/netpol"
	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/control"
	"github.com/ejpir/gantry/internal/sandbox/worker"
	"github.com/ejpir/gantry/internal/vmm"
	"github.com/ejpir/gantry/internal/vmmworker"
)

// Supported: re-exec'd VMM workers are supported on this platform.
const Supported = true

// ErrUnavailable marks "this topology cannot run here" (distinct
// from a spawn failure: auto degrades silently, required fails on both).
var ErrUnavailable = fmt.Errorf("split VMM unavailable on this platform/topology")

// CrossProcNetConn returns a connected pair that survives process
// boundaries (for the in-supervisor netstack ↔ vmm-worker link when
// networking is NOT split but the VMM is).
func CrossProcNetConn() (sup, dev net.Conn, err error) { return worker.SocketpairConns() }

// vmmSplitPossible reports whether the split-VMM topology can run:
// networking must be the embedded netstack (the QEMU-framed conn crosses
// as a descriptor; gvproxy's unixgram endpoint cannot), and shares must
// be hub-served. The real hub stays in the trusted supervisor; the worker
// receives only a request relay, never host share roots.
func vmmSplitPossible(mode string, nw *NetAttachment, shareManager *control.ShareManager) bool {
	if mode == "off" || nw == nil || nw.Conn == nil {
		return false
	}
	if shareManager == nil || shareManager.Hub() == nil {
		return false
	}
	return true
}

// TryStart spawns the _vmm-worker and starts its share relay.
// On success the boot asset descriptors in opts are CONSUMED (closed —
// the worker owns them); on failure they stay open for the monolithic
// fallback. The ShareManager and its pinned roots stay in the trusted
// supervisor in both topologies; the worker gets only bounded FUSE request
// and response bytes over its dedicated share channel. Consequently a
// compromised worker has no host directory descriptor/handle to bypass.
func TryStart(cfg config.RunConfig, opts vmm.Opts, nw *NetAttachment, shareManager *control.ShareManager, dir string, console *os.File) (Runner, error) {
	if !vmmSplitPossible(cfg.ProcessIsolation, nw, shareManager) {
		return nil, ErrUnavailable
	}
	bootCfg := vmmworker.Config{
		MemSize:  opts.MemSize,
		VCPUs:    opts.VCPUs,
		Cmdline:  opts.Cmdline,
		NetMAC:   opts.NetMAC,
		GuestCID: opts.GuestCID,
		HasRoot:  opts.Rootfs != nil,
		NDisksRO: len(opts.DisksRO),
		NDisks:   len(opts.Disks),
	}
	if !opts.BootTimingStart.IsZero() {
		bootCfg.BootTimingStartUnixNano = opts.BootTimingStart.UnixNano()
	}
	// Worker confinement (docs/worker-confinement.md): auto/required
	// self-confines the worker after the descriptor table is consumed.
	// The supervisor pre-creates the private-root mountpoint and passes
	// the hypervisor handle in the table (confinement empties /dev).
	// The KVM open is best-effort: without it the worker's Prepare fails
	// exactly like the monolithic path would.
	bootCfg.Confinement = config.EffectiveProcessIsolation(cfg.ProcessIsolation)
	// Opt-in while the vhost data plane is field-validated. The fallback is
	// the established framed share broker; no persisted sandbox format changes.
	bootCfg.VhostShares = os.Getenv("GANTRY_VHOST_SHARES") == "1"
	bootCfg.HasSharedRAM = bootCfg.VhostShares
	if bootCfg.Confinement != "off" {
		confRoot := filepath.Join(dir, "vmmroot")
		if err := os.MkdirAll(confRoot, 0o700); err != nil {
			return nil, fmt.Errorf("worker confinement root: %w", err)
		}
		bootCfg.ConfRoot = confRoot
	}
	var kvm *os.File
	if f, err := openHypervisorDevice(); err == nil && f != nil {
		kvm = f
		bootCfg.HasKVM = true
	}
	// Local-netstack topology (net-worker degraded, VMM split proceeds):
	// the worker's virtio-net device is the ONLY egress enforcement
	// point — hand it the policy, or a nil policy there is allow-all and
	// every configured deny (including the default local-network wall)
	// silently vanishes. In split-net topology the network worker owns
	// enforcement; its supervisor mirror must not be applied a second time.
	if !nw.Split && nw.Policy != nil {
		raw, err := netpol.Marshal(nw.Policy)
		if err != nil {
			return nil, fmt.Errorf("marshal network policy for worker: %w", err)
		}
		bootCfg.Policy = raw
	}
	var (
		sharedRAM *os.File
		err       error
	)
	if bootCfg.VhostShares {
		sharedRAM, err = newSharedRAM(dir, opts.MemSize)
		if err != nil {
			if kvm != nil {
				_ = kvm.Close()
			}
			return nil, err
		}
	}
	vw, err := spawnVMMWorker(bootCfg, vmmworker.Assets{
		NetConn:   opts.NetConn,
		Console:   console,
		Kernel:    opts.Kernel,
		Rootfs:    opts.Rootfs,
		DisksRO:   opts.DisksRO,
		Disks:     opts.Disks,
		SharedRAM: sharedRAM,
		KVM:       kvm,
	}, dir)
	if err != nil {
		if sharedRAM != nil {
			_ = sharedRAM.Close()
		}
		if kvm != nil {
			_ = kvm.Close()
		}
		return nil, err
	}
	if bootCfg.Policy != nil && nw.Traffic != nil {
		// Attach the host recorder before starting any other lifecycle
		// goroutine: an immediately-failing share relay can initiate Close.
		vw.startTrafficSync(nw.Traffic)
	}
	if bootCfg.VhostShares {
		err = vw.startShareVhost(shareManager.Hub())
	} else {
		err = vw.startShareBroker(shareManager.Hub())
	}
	if err != nil {
		_ = vw.Close()
		return nil, fmt.Errorf("share backend: %w", err)
	}
	return vw, nil
}

// syncWorkerTraffic pulls enforcement counters from the worker into the
// supervisor's recorder until lifecycle completion or worker death. The
// lifecycle RPC response carries the final snapshot; a post-Done RPC cannot.
func syncWorkerTraffic(ctx context.Context, vw *vmmWorker, epoch *netpol.TrafficEpoch, interval time.Duration, done chan<- struct{}) {
	ticker := time.NewTicker(interval)
	defer func() {
		ticker.Stop()
		close(done)
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case <-vw.Done():
			return
		case <-ticker.C:
			if snap, err := vw.trafficSnapshotContext(ctx); err == nil {
				epoch.Merge(snap)
			}
		}
	}
}
