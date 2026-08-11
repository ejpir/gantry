//go:build windows

package virtio

import (
	"fmt"
	"net"
	"os"
)

// VhostQueueFiles is kept wire/topology-compatible with Unix. Windows will
// replace these file descriptors with duplicated Event handles when split VMM
// support is enabled.
type VhostQueueFiles struct {
	KickRead  *os.File
	KickWrite *os.File
	CallRead  *os.File
	CallWrite *os.File
}

type VhostEndpoint struct{}

func NewVhostEndpoint(net.Conn, []VhostQueueFiles) (*VhostEndpoint, error) {
	return nil, fmt.Errorf("vhost-fs is not implemented on Windows")
}

func (*VhostEndpoint) Close() error { return nil }

func (*VhostEndpoint) NewDevice(string, *os.File, uint64, uint64) (Device, error) {
	return nil, fmt.Errorf("vhost-fs is not implemented on Windows")
}
