package client

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ejpir/gantry/internal/shares"

	mountapi "github.com/containerd/nerdbox/api/services/mount/v1"
)

// ShareEntry is one entry of the VMM's shares.json manifest.
type ShareEntry = shares.Entry

// LoadShareManifest reads the manifest next to a sandbox's RPC socket. A
// missing or malformed manifest means no shares.
//
// Two manifest shapes remain live by design: persistent sandboxes produce the
// versioned hub transport, while current direct `gantry run` and one-shot exec
// flows produce an unversioned per-device manifest. Existing sandbox state may
// contain either shape, so a nil Transport is not dead compatibility code.
func LoadShareManifest(dir string) shares.Manifest {
	payload, err := os.ReadFile(filepath.Join(dir, "shares.json"))
	if err != nil {
		return shares.Manifest{}
	}
	var manifest shares.Manifest
	if json.Unmarshal(payload, &manifest) != nil {
		return shares.Manifest{}
	}
	return manifest
}

// LoadShares returns the logical entries from shares.json.
func LoadShares(dir string) []ShareEntry {
	return LoadShareManifest(dir).Shares
}

// mountShares establishes the guest-side virtio-fs mounts. A hub is one
// permanent device with logical children. A nil transport is the live direct-
// run protocol, where every entry is its own virtio-fs device.
func mountShares(ctx context.Context, client mountapi.TTRPCMountService, entries []ShareEntry, transport *shares.Transport, logf func(string, ...any)) (bool, error) {
	if transport != nil {
		_, err := client.MountAll(ctx, &mountapi.MountAllRequest{Mounts: []*mountapi.MountSpec{{
			Type: "virtiofs", Source: transport.Tag, Target: transport.VMPath,
		}}})
		if err != nil {
			if !errHas(err, errTextMountBusy) {
				return false, fmt.Errorf("mount virtio-fs share hub: %w", err)
			}
			logf("share hub %-6s already mounted at %s", transport.Tag, transport.VMPath)
		} else {
			logf("share hub %-6s %-28s -> %s", transport.Tag, "(dynamic)", transport.VMPath)
		}
		for _, entry := range entries {
			logf("share %-12s %-30s -> %s -> container %s (%s, %s)", entry.Tag, entry.Path, entry.VMPath, entry.CtrPath, shareMode(entry), defaultShareState(entry.State))
		}
		// The mount service deliberately treats an identical existing mount as
		// success and does not report whether this call created it. The hub is a
		// sandbox-lifetime resource, so sessions must never claim or unmount it.
		return false, nil
	}
	if len(entries) == 0 {
		return false, nil
	}

	mounts := make([]*mountapi.MountSpec, 0, len(entries))
	for _, entry := range entries {
		mount := &mountapi.MountSpec{Type: "virtiofs", Source: entry.Tag, Target: entry.VMPath}
		if entry.RO {
			mount.Options = []string{"ro"}
		}
		mounts = append(mounts, mount)
	}
	if _, err := client.MountAll(ctx, &mountapi.MountAllRequest{Mounts: mounts}); err != nil {
		// MountAll is not documented as transactional. Roll back every target
		// from this request if it reports a partial failure.
		return true, fmt.Errorf("mount virtio-fs shares: %w", err)
	}
	for _, entry := range entries {
		logf("share %-12s %-30s -> %s -> container %s (%s)", entry.Tag, entry.Path, entry.VMPath, entry.CtrPath, shareMode(entry))
	}
	return true, nil
}

func shareMode(entry ShareEntry) string {
	if entry.RO {
		return "ro"
	}
	return "rw"
}

func defaultShareState(state string) string {
	if state == "" {
		return "active"
	}
	return state
}

func unmountShares(ctx context.Context, client mountapi.TTRPCMountService, entries []ShareEntry, transport *shares.Transport, report func(string, ...any)) {
	if transport != nil {
		if _, err := client.Unmount(ctx, &mountapi.UnmountRequest{Target: transport.VMPath}); err != nil {
			report("client: unmount share hub: %v\n", err)
		}
		return
	}
	for i := len(entries) - 1; i >= 0; i-- {
		if _, err := client.Unmount(ctx, &mountapi.UnmountRequest{Target: entries[i].VMPath}); err != nil {
			report("client: unmount share %s: %v\n", entries[i].Tag, err)
		}
	}
}
