//go:build linux || darwin

package workerconf

// probeReadPath is the canonical "read a user-visible host file" probe
// target for Verify.
const probeReadPath = "/etc/passwd"
