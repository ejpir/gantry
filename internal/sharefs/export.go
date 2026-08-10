//go:build linux || darwin || windows

package sharefs

import (
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fs"
)

// ExportState is the lifecycle of one logical share beneath the hub.
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

// Export is one prepared or published child of a Hub.
type Export struct {
	Tag  string
	Path string
	RO   bool
	UID  *uint32
	GID  *uint32

	identity Identity

	state atomic.Int32
	// node is the platform backend's root node, presented at /<tag>.
	node  fs.InodeEmbedder
	inode *fs.Inode
	// release drops the platform backend's pinned host resources (root
	// FD or handle). It runs at most once, from finish.
	release   func()
	onFinish  func(*Export)
	finishOne sync.Once
}

// State reports the export lifecycle for the control plane and dashboard.
func (e *Export) State() ExportState {
	if e == nil {
		return ExportGone
	}
	return ExportState(e.state.Load())
}

// Identity returns the kernel-object identity pinned by this export.
func (e *Export) Identity() Identity {
	if e == nil {
		return Identity{}
	}
	return e.identity
}

func (e *Export) advanceState(next ExportState) {
	if e == nil {
		return
	}
	for {
		current := e.state.Load()
		if current >= int32(next) || e.state.CompareAndSwap(current, int32(next)) {
			return
		}
	}
}

func (e *Export) usable() bool {
	state := e.State()
	return state == ExportActive || state == ExportDraining
}

func (e *Export) mutable() syscall.Errno {
	if !e.usable() {
		return syscall.ESTALE
	}
	if e.RO {
		return syscall.EROFS
	}
	return 0
}

func (e *Export) finish() {
	if e == nil {
		return
	}
	e.finishOne.Do(func() {
		e.advanceState(ExportGone)
		if e.release != nil {
			e.release()
		}
		if e.onFinish != nil {
			e.onFinish(e)
		}
	})
}

// Prepared is a fully validated export that has not entered the live
// namespace. Splitting preparation from publication lets the sandbox manager
// persist sandbox.json before making an infallible map swap. Publish and Swap
// consume it on success; Close releases it on failure.
type Prepared struct {
	export *Export
}

// Close releases a prepared export that was never published.
func (p *Prepared) Close() {
	if p != nil && p.export != nil {
		export := p.export
		p.export = nil
		export.finish()
	}
}

// Identity returns the candidate's pinned root identity.
func (p *Prepared) Identity() Identity {
	if p == nil || p.export == nil {
		return Identity{}
	}
	return p.export.identity
}
