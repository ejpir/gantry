//go:build linux || darwin

package networker

// Unix network workers can install and verify a platform confinement tier.
const ConfinementPlatform = true
