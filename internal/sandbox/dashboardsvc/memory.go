package dashboardsvc

import "github.com/ejpir/gantry/internal/sandbox/config"

// dashboardMaxMemoryMB bounds the sliders by total physical RAM, not the
// fluctuating amount of free memory. CLI resource validation remains unchanged.
func dashboardMaxMemoryMB(totalBytes uint64) uint {
	if totalBytes == 0 {
		// If host detection fails, offer the normal VM default rather than 1 TiB.
		totalBytes = 512 << 20
	}
	return uint(max(uint64(config.MinSandboxMemMB), min(totalBytes>>20, uint64(config.MaxSandboxMemMB))))
}
