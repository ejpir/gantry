//go:build !linux && !darwin && !windows

package virtio

import (
	"fmt"
	"io"
)

// ShareExportState mirrors the Unix/Windows implementations for
// cross-platform control-plane code. Platforms outside Linux, macOS, and
// Windows have no host virtio-fs backend.
type ShareExportState int32

const (
	ShareExportActive ShareExportState = iota
	ShareExportDraining
	ShareExportRevoked
	ShareExportGone
)

func (s ShareExportState) String() string {
	switch s {
	case ShareExportActive:
		return "active"
	case ShareExportDraining:
		return "draining"
	case ShareExportRevoked:
		return "revoked"
	default:
		return "gone"
	}
}

type ShareExport struct{}

func (e *ShareExport) State() ShareExportState { return ShareExportGone }

type PreparedShare struct{}

type ShareHub struct{}

// ShareHubProxy exists on unsupported hosts so shared VMM configuration can
// name the portable broker transport. Construction still fails explicitly:
// these platforms have no virtio-fs backend.
type ShareHubProxy struct{}

var errShareHubUnsupported = fmt.Errorf("host directory sharing (virtio-fs) is not supported on this platform")

func NewShareHub() (*ShareHub, error) { return nil, errShareHubUnsupported }
func NewShareHubProxy(io.ReadWriteCloser) (*ShareHubProxy, error) {
	return nil, errShareHubUnsupported
}
func (h *ShareHub) ServeBroker(io.ReadWriteCloser) error { return errShareHubUnsupported }
func (h *ShareHub) Prepare(tag, path string, ro bool) (*PreparedShare, string, error) {
	return nil, "", errShareHubUnsupported
}
func (p *PreparedShare) ClosePrepared() {}
func (h *ShareHub) Publish(p *PreparedShare) (*ShareExport, error) {
	return nil, errShareHubUnsupported
}
func (h *ShareHub) Export(tag string) *ShareExport { return nil }
func (h *ShareHub) Exports() []*ShareExport        { return nil }
func (h *ShareHub) Remove(tag string, force bool) (*ShareExport, error) {
	return nil, errShareHubUnsupported
}
func (h *ShareHub) Close() error      { return nil }
func (h *ShareHub) Tag() string       { return "gantry-shares" }
func (p *ShareHubProxy) Tag() string  { return "gantry-shares" }
func (p *ShareHubProxy) Close() error { return nil }
