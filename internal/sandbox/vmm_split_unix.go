//go:build linux || darwin

package sandbox

// Split-VMM launch (unix): the descriptor table, SCM_RIGHTS channel, and
// re-exec all exist here. See docs/vmm-network-isolation.md phase 2.

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"

	"github.com/ejpir/gantry/internal/virtio"
	"github.com/ejpir/gantry/internal/vmm"
)

// vmmWorkerPlatform: re-exec'd VMM workers are supported on this platform.
const vmmWorkerPlatform = true

// errVMMSplitUnavailable marks "this topology cannot run here" (distinct
// from a spawn failure: auto degrades silently, required fails on both).
var errVMMSplitUnavailable = fmt.Errorf("split VMM unavailable on this platform/topology")

// crossProcNetConn returns a connected pair that survives process
// boundaries (for the in-supervisor netstack ↔ vmm-worker link when
// networking is NOT split but the VMM is).
func crossProcNetConn() (sup, dev net.Conn, err error) { return socketpairConns() }

// vmmSplitPossible reports whether the split-VMM topology can run:
// networking must be the embedded netstack (the QEMU-framed conn crosses
// as a descriptor; gvproxy's unixgram endpoint cannot), and shares must
// be hub-served (legacy per-device shares resolve host paths).
func vmmSplitPossible(mode string, nw *Network, shareManager *ShareManager) bool {
	if mode == "off" || nw == nil || nw.Conn == nil {
		return false
	}
	if shareManager != nil && shareManager.Hub() == nil && len(shareManager.Entries()) > 0 {
		return false
	}
	return true
}

// tryStartVMMSplit spawns the _vmm-worker and rewires the share backend.
// On success the boot asset descriptors in opts are CONSUMED (closed —
// the worker owns them); on failure they stay open for the monolithic
// fallback. The ShareManager gains mirror bookkeeping plus the RPC
// backend for post-boot hot-adds.
func tryStartVMMSplit(cfg RunConfig, opts vmm.Opts, nw *Network, shareManager *ShareManager, dir string, console *os.File) (vmmRunner, error) {
	if !vmmSplitPossible(cfg.ProcessIsolation, nw, shareManager) {
		return nil, errVMMSplitUnavailable
	}
	var metas []vmmShareMeta
	var roots []*os.File
	if shareManager != nil && shareManager.Hub() != nil {
		var err error
		metas, roots, err = shareManager.SplitBootAssets()
		if err != nil {
			return nil, fmt.Errorf("share boot assets: %w", err)
		}
	}
	bootCfg := vmmBootConfig{
		MemSize:  opts.MemSize,
		VCPUs:    opts.VCPUs,
		Cmdline:  opts.Cmdline,
		NetMAC:   opts.NetMAC,
		GuestCID: opts.GuestCID,
		HasRoot:  opts.Rootfs != nil,
		NDisksRO: len(opts.DisksRO),
		NDisks:   len(opts.Disks),
		Shares:   metas,
	}
	vw, err := spawnVMMWorker(bootCfg, vmmWorkerAssets{
		NetConn:    opts.NetConn,
		Console:    console,
		Kernel:     opts.Kernel,
		Rootfs:     opts.Rootfs,
		DisksRO:    opts.DisksRO,
		Disks:      opts.Disks,
		ShareRoots: roots,
	}, dir)
	if err != nil {
		for _, r := range roots {
			_ = r.Close()
		}
		return nil, err
	}
	if shareManager != nil && shareManager.Hub() != nil {
		// The local hub's pinned roots are superseded by the worker's
		// (transferred) ones; bookkeeping moves to mirror records.
		shareManager.DetachServing()
		shareManager.SetServing(workerShareServing{w: vw})
	}
	return vw, nil
}

// SplitBootAssets pins one root descriptor per configured export for the
// vmm worker's descriptor table and installs mirror bookkeeping. Path
// strings are canonicalized for the manifest; serving resolves through
// the descriptors themselves, never the strings. Order is deterministic
// (sorted by tag).
func (m *ShareManager) SplitBootAssets() ([]vmmShareMeta, []*os.File, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	tags := make([]string, 0, len(m.exports))
	for tag := range m.exports {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	var metas []vmmShareMeta
	var roots []*os.File
	for _, tag := range tags {
		ms := m.exports[tag]
		root, err := virtio.OpenShareRootFD(ms.share.Path)
		if err != nil {
			for _, r := range roots {
				_ = r.Close()
			}
			return nil, nil, fmt.Errorf("share %s: %w", tag, err)
		}
		canon := ms.share.Path
		if resolved, err := filepath.EvalSymlinks(canon); err == nil {
			canon = resolved
		}
		ms.share.Path = canon
		ms.export = virtio.NewShareExportMirror(tag, canon, ms.share.RO, ms.share.UID, ms.share.GID, virtio.ShareExportActive)
		metas = append(metas, vmmShareMeta{Tag: tag, Path: canon, RO: ms.share.RO, UID: ms.share.UID, GID: ms.share.GID})
		roots = append(roots, root)
	}
	return metas, roots, nil
}
