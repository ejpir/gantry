//go:build linux

package sandbox

// spike_rootfs_linux.go — the preferred host preparation: the same shape
// containerd's overlayfs snapshotter would hand a shim. The cached EROFS
// image is loop-mounted read-only as the lower layer, a scratch upper carries
// the spike fixtures, and the merged overlay is what gets exported. When the
// kernel lacks EROFS or overlayfs (or the spike runs unprivileged), it falls
// back to the extracted-directory snapshot.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/ejpir/gantry/internal/sandbox/config"
)

func prepareRootfsSnapshot(cfg config.RunConfig, staging string) (*rootfsSnapshotPrep, error) {
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "gantry _rootfs-spike: not root — using the extracted-directory snapshot (no erofs/overlay mounts)")
		return prepareDirSnapshot(cfg, staging)
	}
	prep, err := prepareOverlaySnapshot(cfg, staging)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gantry _rootfs-spike: overlay snapshot unavailable (%v) — falling back to the extracted-directory snapshot\n", err)
		return prepareDirSnapshot(cfg, staging)
	}
	return prep, nil
}

// prepareOverlaySnapshot mounts the cached image as the overlay's lower layer
// and populates a scratch upper layer with the spike fixtures.
func prepareOverlaySnapshot(cfg config.RunConfig, staging string) (*rootfsSnapshotPrep, error) {
	if cfg.LayerSet != nil {
		return nil, fmt.Errorf("layerset images are not supported by the rootfs spike yet; use a flattened image")
	}
	if cfg.Image == "" {
		return nil, fmt.Errorf("no flattened image in the resolved configuration")
	}
	if _, err := os.Stat(cfg.Image); err != nil {
		return nil, fmt.Errorf("cached image: %w", err)
	}

	dir, err := os.MkdirTemp(staging, "gantry-rootfs-spike-")
	if err != nil {
		return nil, err
	}
	prep := &rootfsSnapshotPrep{
		dir:      dir,
		lower:    filepath.Join(dir, "lower"),
		upper:    filepath.Join(dir, "upper"),
		snapshot: filepath.Join(dir, "snapshot"),
	}
	prep.writeVerifyDir = prep.upper
	work := filepath.Join(dir, "work")
	for _, sub := range []string{prep.lower, prep.upper, work, prep.snapshot} {
		if err := os.Mkdir(sub, 0o755); err != nil {
			prep.Cleanup()
			return nil, err
		}
	}
	out, err := exec.Command("mount", "-o", "ro,loop", "-t", "erofs", cfg.Image, prep.lower).CombinedOutput()
	if err != nil {
		prep.Cleanup()
		return nil, fmt.Errorf("mount erofs image: %w: %s (kernel needs CONFIG_EROFS_FS — try: modprobe erofs)", err, strings.TrimSpace(string(out)))
	}
	prep.mountedLower = true
	if err := prep.populateFixtures(prep.upper); err != nil {
		prep.Cleanup()
		return nil, err
	}
	options := fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s", prep.lower, prep.upper, work)
	out, err = exec.Command("mount", "-t", "overlay", "overlay", "-o", options, prep.snapshot).CombinedOutput()
	if err != nil {
		prep.Cleanup()
		return nil, fmt.Errorf("mount overlay: %w: %s", err, strings.TrimSpace(string(out)))
	}
	prep.mountedSnap = true
	// The whiteout goes in AFTER the overlay mount: field tests on
	// AL2023's patched overlayfs (6.1.177-224.371.amzn2023) showed whiteouts
	// created before the mount are silently ignored, leaking the lower file.
	if err := prep.placeWhiteout(); err != nil {
		prep.Cleanup()
		return nil, err
	}
	// Verify through the merged view from the host: a kernel that ignores
	// the whiteout must fail the spike loudly here, not leak into the guest.
	if _, err := os.Stat(filepath.Join(prep.snapshot, strings.TrimPrefix(prep.whiteoutPath, "/"))); !os.IsNotExist(err) {
		prep.Cleanup()
		return nil, fmt.Errorf("host kernel does not honor the overlay whiteout for %s (stat err %v) — this platform cannot serve containerd-style snapshots", prep.whiteoutPath, err)
	}
	return prep, nil
}

// placeWhiteout hides one lower-layer file and records the guest path the
// checker must not see. The whiteout is created by REMOVING the file
// through the merged overlay view: the kernel then records whatever at-rest
// whiteout form it honors. Field tests on AL2023's patched overlayfs
// (6.1.177-224.371.amzn2023) showed manually crafted .wh. char devices are
// silently ignored over an erofs lower (same-named mode-000 nodes work),
// while rm-through-overlay works on every tested combination. The caller
// verifies the effect through the merged view.
func (p *rootfsSnapshotPrep) placeWhiteout() error {
	for _, candidate := range []string{"etc/alpine-release", "etc/lsb-release", "etc/debian_version"} {
		merged := filepath.Join(p.snapshot, candidate)
		if _, err := os.Stat(merged); err != nil {
			continue
		}
		if err := os.Remove(merged); err != nil {
			return fmt.Errorf("whiteout /%s through the merged view: %w", candidate, err)
		}
		p.whiteoutPath = "/" + candidate
		return nil
	}
	return fmt.Errorf("no known lower-layer file to whiteout (looked for alpine/lsb/debian release markers)")
}
