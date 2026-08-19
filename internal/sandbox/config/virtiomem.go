package config

import (
	"os"
	"runtime"
	"strings"
)

// VirtioMemWorkerSetting resolves GANTRY_VIRTIO_MEM into the explicit value
// passed down to a worker process. It is a settings reader rather than worker
// machinery, so it lives with the rest of the run configuration.
func VirtioMemWorkerSetting() string {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("GANTRY_VIRTIO_MEM"))) {
	case "1", "true", "yes", "on":
		return "1"
	case "0", "false", "no", "off":
		return "0"
	case "":
		if runtime.GOOS == "windows" {
			return "1"
		}
		return ""
	default:
		// Preserve the VMM's conservative handling of unknown values. Windows
		// workers need an explicit zero so their platform default does not turn
		// an invalid parent setting back on.
		if runtime.GOOS == "windows" {
			return "0"
		}
		return ""
	}
}
