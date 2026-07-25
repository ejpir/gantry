//go:build windows

package main

import "fmt"

// addShare: virtio-fs needs a host FUSE server; our go-fuse loopback only
// builds on linux/darwin. A Windows port would use WinFsp — not implemented.
func (m *machine) addShare(share hostShare) error {
	return fmt.Errorf("host directory sharing (virtio-fs) is not supported on Windows yet (tag %q)", share.tag)
}
