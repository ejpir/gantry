//go:build !linux && !darwin

package sandbox

// The dynamic-rootfs spike's host preparation exists for Linux and macOS.

import (
	"fmt"

	"github.com/ejpir/gantry/internal/sandbox/config"
)

func prepareRootfsSnapshot(config.RunConfig, string) (*rootfsSnapshotPrep, error) {
	return nil, fmt.Errorf("the rootfs spike is supported on Linux and macOS hosts; run it on a KVM node or Apple Silicon")
}

// pickStagingDir is never reached: prepareRootfsSnapshot fails first. It
// exists so the platform-neutral spike code links.
func pickStagingDir(preferred string) (string, error) {
	return preferred, nil
}
