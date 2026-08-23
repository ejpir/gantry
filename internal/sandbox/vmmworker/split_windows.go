package vmmworker

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/ejpir/gantry/internal/netpol"
	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/control"
	"github.com/ejpir/gantry/internal/sandbox/worker"
	"github.com/ejpir/gantry/internal/vmm"
	vmmworkerapi "github.com/ejpir/gantry/internal/vmmworker"
	"github.com/ejpir/gantry/internal/workerproto"
)

const Supported = true

var ErrUnavailable = fmt.Errorf("split VMM unavailable on this platform/topology")

func CrossProcNetConn() (sup, dev net.Conn, err error) { return worker.SocketpairConns() }

func vmmSplitPossible(mode string, nw *NetAttachment, shareManager *control.ShareManager) bool {
	return mode != "off" && nw != nil && nw.Conn != nil &&
		shareManager != nil && shareManager.Hub() != nil
}

func TryStart(cfg config.RunConfig, opts vmm.Opts, nw *NetAttachment, shareManager *control.ShareManager, dir string, console *os.File) (Runner, error) {
	if !vmmSplitPossible(cfg.ProcessIsolation, nw, shareManager) {
		return nil, ErrUnavailable
	}
	bootCfg := vmmworkerapi.Config{
		MemSize: opts.MemSize, VCPUs: opts.VCPUs, Cmdline: opts.Cmdline,
		NetMAC: opts.NetMAC, GuestCID: opts.GuestCID, HasRoot: opts.Rootfs != nil,
		NDisksRO: len(opts.DisksRO), NDisks: len(opts.Disks),
		Confinement: config.NormalizeProcessIsolation(cfg.ProcessIsolation),
	}
	if !opts.BootTimingStart.IsZero() {
		bootCfg.BootTimingStartUnixNano = opts.BootTimingStart.UnixNano()
	}
	// Brokered WHPX keeps the opaque partition in a narrow full-token process
	// while device emulation runs in the AppContainer VMM worker. Auto mode may
	// fall back to the established Job-only worker if broker setup is unavailable.
	bootCfg.VhostShares = false
	brokeredWHPX := bootCfg.Confinement != "off" && os.Getenv("GANTRY_WINDOWS_WHPX_BROKER") != "0"
	var sharedRAM *os.File
	if brokeredWHPX {
		rawToken, err := workerproto.NewNonce()
		if err != nil {
			return nil, fmt.Errorf("WHPX broker peer token: %w", err)
		}
		token := hex.EncodeToString(rawToken)
		sharedRAM, err = newSharedRAM(dir, opts.MemSize)
		if err != nil {
			return nil, err
		}
		bootCfg.HasSharedRAM = true
		bootCfg.WHPXBroker = true
		bootCfg.WHPXToken = token
	}
	if !nw.Split && nw.Policy != nil {
		raw, err := netpol.Marshal(nw.Policy)
		if err != nil {
			return nil, fmt.Errorf("marshal network policy for worker: %w", err)
		}
		bootCfg.Policy = raw
	}
	workerAssets := vmmworkerapi.Assets{
		NetConn: opts.NetConn, Console: console, Kernel: opts.Kernel,
		Rootfs: opts.Rootfs, DisksRO: opts.DisksRO, Disks: opts.Disks,
		SharedRAM: sharedRAM,
	}
	vw, err := spawnVMMWorker(bootCfg, workerAssets, dir)
	if err != nil && brokeredWHPX && bootCfg.Confinement != "required" {
		if sharedRAM != nil {
			_ = sharedRAM.Close()
		}
		fmt.Fprintf(os.Stderr, "daemon: brokered WHPX unavailable (%v), retrying with Job-only VMM confinement\n", err)
		bootCfg.WHPXBroker = false
		bootCfg.WHPXToken = ""
		bootCfg.HasSharedRAM = false
		workerAssets.SharedRAM = nil
		vw, err = spawnVMMWorker(bootCfg, workerAssets, dir)
	}
	if err != nil {
		if sharedRAM != nil {
			_ = sharedRAM.Close()
		}
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
