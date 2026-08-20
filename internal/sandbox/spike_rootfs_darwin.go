//go:build darwin

package sandbox

// macOS has no erofs/overlay mounts; the spike uses the extracted-directory
// snapshot. The virtio-fs export path under test is identical, and the guest
// sees the same tree a native snapshotter would produce.

import (
	"github.com/ejpir/gantry/internal/sandbox/config"
)

func prepareRootfsSnapshot(cfg config.RunConfig, staging string) (*rootfsSnapshotPrep, error) {
	return prepareDirSnapshot(cfg, staging)
}
