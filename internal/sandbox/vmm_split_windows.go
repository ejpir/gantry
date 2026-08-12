package sandbox

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/ejpir/gantry/internal/netpol"
	"github.com/ejpir/gantry/internal/vmm"
	"github.com/ejpir/gantry/internal/vmmworker"
)

const vmmWorkerPlatform = true

var errVMMSplitUnavailable = fmt.Errorf("split VMM unavailable on this platform/topology")

func crossProcNetConn() (sup, dev net.Conn, err error) { return socketpairConns() }

func vmmSplitPossible(mode string, nw *Network, shareManager *ShareManager) bool {
	return mode != "off" && nw != nil && nw.Conn != nil &&
		shareManager != nil && shareManager.Hub() != nil
}

func tryStartVMMSplit(cfg RunConfig, opts vmm.Opts, nw *Network, shareManager *ShareManager, dir string, console *os.File) (vmmRunner, error) {
	if !vmmSplitPossible(cfg.ProcessIsolation, nw, shareManager) {
		return nil, errVMMSplitUnavailable
	}
	bootCfg := vmmworker.Config{
		MemSize: opts.MemSize, VCPUs: opts.VCPUs, Cmdline: opts.Cmdline,
		NetMAC: opts.NetMAC, GuestCID: opts.GuestCID, HasRoot: opts.Rootfs != nil,
		NDisksRO: len(opts.DisksRO), NDisks: len(opts.Disks),
		Confinement: effectiveProcessIsolation(cfg.ProcessIsolation),
	}
	if !opts.BootTimingStart.IsZero() {
		bootCfg.BootTimingStartUnixNano = opts.BootTimingStart.UnixNano()
	}
	// WHPX does not use a pre-opened hypervisor device, and the experimental
	// Unix vhost shared-memory backend is deliberately not enabled here.
	bootCfg.VhostShares = false
	bootCfg.HasSharedRAM = false
	if !nw.Split && nw.Policy != nil {
		raw, err := netpol.Marshal(nw.Policy)
		if err != nil {
			return nil, fmt.Errorf("marshal network policy for worker: %w", err)
		}
		bootCfg.Policy = raw
	}
	vw, err := spawnVMMWorker(bootCfg, vmmworker.Assets{
		NetConn: opts.NetConn, Console: console, Kernel: opts.Kernel,
		Rootfs: opts.Rootfs, DisksRO: opts.DisksRO, Disks: opts.Disks,
	}, dir)
	if err != nil {
		return nil, err
	}
	if bootCfg.Policy != nil && nw.Traffic != nil {
		vw.startTrafficSync(nw.Traffic)
	}
	if err := vw.startShareBroker(shareManager.Hub()); err != nil {
		_ = vw.Close()
		return nil, fmt.Errorf("share backend: %w", err)
	}
	return vw, nil
}

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
