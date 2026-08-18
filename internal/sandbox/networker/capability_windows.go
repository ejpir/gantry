//go:build windows

package networker

// Windows can re-exec the network worker, but networkworker confinement is
// intentionally unavailable there. Auto mode should take its fallback before
// spawning a child that can only reject the bootstrap.
const ConfinementPlatform = false
