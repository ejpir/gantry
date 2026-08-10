//go:build !linux && !darwin && !windows

package sharefs

import (
	"fmt"
)

// ExportState mirrors the Unix/Windows implementations for
// cross-platform control-plane code. Platforms outside Linux, macOS, and
// Windows have no host virtio-fs backend.
type ExportState int32

const (
	ExportActive ExportState = iota
	ExportDraining
	ExportRevoked
	ExportGone
)

func (s ExportState) String() string {
	switch s {
	case ExportActive:
		return "active"
	case ExportDraining:
		return "draining"
	case ExportRevoked:
		return "revoked"
	default:
		return "gone"
	}
}

type Export struct{}

func (e *Export) State() ExportState { return ExportGone }
func (e *Export) Identity() Identity { return Identity{} }

type Prepared struct{}

func (p *Prepared) Identity() Identity { return Identity{} }

type Hub struct{}

var errUnsupported = fmt.Errorf("host directory sharing (virtio-fs) is not supported on this platform")

func NewHub() (*Hub, error) { return nil, errUnsupported }
func (h *Hub) Prepare(tag, path string, ro bool) (*Prepared, string, error) {
	return nil, "", errUnsupported
}
func (h *Hub) PrepareMapped(tag, path string, ro bool, uid, gid *uint32) (*Prepared, string, error) {
	return nil, "", errUnsupported
}
func (p *Prepared) Close()                          {}
func (h *Hub) Publish(p *Prepared) (*Export, error) { return nil, errUnsupported }
func (h *Hub) Swap(p *Prepared) (old, export *Export, err error) {
	return nil, nil, errUnsupported
}
func (h *Hub) Export(tag string) *Export                      { return nil }
func (h *Hub) Exports() []*Export                             { return nil }
func (h *Hub) Remove(tag string, force bool) (*Export, error) { return nil, errUnsupported }
func (h *Hub) Close() error                                   { return nil }
