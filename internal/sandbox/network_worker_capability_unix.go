//go:build linux || darwin

package sandbox

// Unix network workers can install and verify a platform confinement tier.
const networkWorkerConfinementPlatform = true
