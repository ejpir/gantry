package sandbox

// spike_rootfs.go — hidden `gantry _rootfs-spike` command
// (docs/kubernetes-runtimeclass.md, Phase K0). Verifies the second
// existential RuntimeClass risk: a host directory prepared after VM boot (a
// containerd-style overlay snapshot over the cached EROFS image) can be
// exported through the permanent virtio-fs hub, bound by the guest agent as a
// task bundle rootfs, and used by the guest runtime with correct OCI rootfs
// semantics — including host-enforced read-only exports — at measurable
// performance.

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/ejpir/gantry/internal/client"
)

const (
	rootfsSpikeExportRW = "mcrootfs"
	rootfsSpikeExportRO = "mcrootfs-ro"
)

// rootfsSnapshotPrep describes the prepared host snapshot. Linux prefers an
// erofs+overlay mount (mounted* flags set); the extracted-directory path
// leaves them clear and verifies guest writes in the snapshot directory
// itself.
type rootfsSnapshotPrep struct {
	dir            string
	lower          string
	upper          string
	snapshot       string
	whiteoutPath   string
	writeVerifyDir string
	mountedLower   bool
	mountedSnap    bool
}

// Cleanup unmounts whatever was mounted and removes the staging directory.
// Best effort: failures are reported but never mask the spike result.
func (p *rootfsSnapshotPrep) Cleanup() {
	if p == nil {
		return
	}
	for _, mount := range []struct {
		held  bool
		point string
	}{{p.mountedSnap, p.snapshot}, {p.mountedLower, p.lower}} {
		if !mount.held {
			continue
		}
		if out, err := exec.Command("umount", mount.point).CombinedOutput(); err != nil {
			fmt.Fprintf(os.Stderr, "gantry _rootfs-spike: umount %s: %v: %s\n", mount.point, err, strings.TrimSpace(string(out)))
		}
	}
	if p.dir != "" {
		_ = os.RemoveAll(p.dir)
	}
}

// CmdRootfsSpike implements `gantry _rootfs-spike`.
func CmdRootfsSpike(argv []string) int {
	launch, code := prepareSpikeLaunch(argv, "_rootfs-spike", `examples:
  gantry _rootfs-spike rf1 -image alpine:latest
  gantry _rootfs-spike rf2 -image ubuntu:latest -runtime runsc`)
	if launch == nil {
		return code
	}
	// Stage on a filesystem with user-xattr support: the sandbox state dir
	// can land on tmpfs (HOME unresolvable under SSM → os.TempDir), and
	// tmpfs before kernel 6.6 cannot store user xattrs.
	staging, err := pickStagingDir(filepath.Join(launch.dir, "_rootfs-spike"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "gantry _rootfs-spike:", err)
		return 1
	}
	prep, err := prepareRootfsSnapshot(launch.cfg, staging)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gantry _rootfs-spike:", err)
		return 1
	}
	defer prep.Cleanup()
	return launch.run(func(d *daemonRuntime) int { return d.runRootfsSpike(prep) })
}

// runRootfsSpike is the _rootfs-spike scenario hook. It publishes the
// prepared snapshot as two hub exports (writable and host-enforced
// read-only), drives the guest scenario, and then verifies host-visible
// effects before the normal VM shutdown.
func (d *daemonRuntime) runRootfsSpike(prep *rootfsSnapshotPrep) int {
	image := d.cfg.ImageRef
	if image == "" {
		image = d.cfg.Image
	}
	runtimeName := d.cfg.Runtime
	if runtimeName == "" {
		runtimeName = "crun"
	}
	fmt.Fprintf(os.Stdout, "rootfs-spike: host snapshot %s (image %s, guest runtime %s)\n", prep.snapshot, image, runtimeName)

	hub := d.shares.Hub()
	if hub == nil {
		fmt.Fprintln(os.Stderr, "gantry _rootfs-spike: the virtio-fs share hub is unavailable on this platform")
		return 1
	}
	release := func() {}
	for _, export := range []struct {
		tag string
		ro  bool
	}{
		{rootfsSpikeExportRW, false},
		{rootfsSpikeExportRO, true},
	} {
		prepared, _, err := hub.Prepare(export.tag, prep.snapshot, export.ro)
		if err != nil {
			fmt.Fprintln(os.Stderr, "gantry _rootfs-spike: prepare export:", err)
			return 1
		}
		if _, err := hub.Publish(prepared); err != nil {
			fmt.Fprintln(os.Stderr, "gantry _rootfs-spike: publish export:", err)
			return 1
		}
		prev := release
		release = func() { _, _ = hub.Remove(export.tag, true); prev() }
	}
	defer release()

	_, spikeErr := client.RootfsSpike(d.rpc, client.RootfsSpikeOptions{
		StreamSock:   d.broker.streamSock,
		StreamDial:   d.broker.streamDial,
		Report:       os.Stdout,
		ExportTag:    rootfsSpikeExportRW,
		ROTag:        rootfsSpikeExportRO,
		WhiteoutPath: prep.whiteoutPath,
	})

	// Host-side evidence: the guest's fsynced write must have landed in the
	// overlay upper directory through the export.
	if written, readErr := os.ReadFile(filepath.Join(prep.writeVerifyDir, "spike-guest-write")); readErr != nil || string(written) != "from-guest\n" {
		spikeErr = errors.Join(spikeErr, fmt.Errorf("host-visible guest write: %v (content %q)", readErr, written))
		fmt.Fprintln(os.Stdout, "rootfs-spike: FAIL host-visible guest write")
	} else {
		fmt.Fprintln(os.Stdout, "rootfs-spike: PASS host-visible guest write — upper dir received the fsynced file")
	}

	stopCode := d.gracefulStop("rootfs-spike complete")
	if spikeErr != nil {
		fmt.Fprintln(os.Stderr, "gantry _rootfs-spike:", spikeErr)
		return 1
	}
	return stopCode
}
