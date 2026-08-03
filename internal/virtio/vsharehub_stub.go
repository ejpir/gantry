//go:build !linux && !darwin && !windows

package virtio

import "fmt"

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

var errShareHubUnsupported = fmt.Errorf("host directory sharing (virtio-fs) is not supported on this platform")

func NewShareHub() (*ShareHub, error) { return nil, errShareHubUnsupported }
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
func (h *ShareHub) Close() error { return nil }
func (h *ShareHub) Tag() string  { return "gantry-shares" }
