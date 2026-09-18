//go:build linux || darwin || windows

package sharefs

import (
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/ejpir/gantry/internal/sharefs/exportstate"
	"github.com/ejpir/gantry/internal/sharefs/preparedstate"
	"github.com/hanwen/go-fuse/v2/fs"
)

// FUSE carries Linux renameat2 flags on every host. NOREPLACE and EXCHANGE
// only rename existing directory entries; WHITEOUT can create a privileged
// character device and therefore bypass the share's Mknod denial.
const allowedGuestRenameFlags = uint32(1 | 2)

func validateGuestRenameFlags(flags uint32) syscall.Errno {
	if flags & ^allowedGuestRenameFlags != 0 {
		return syscall.EPERM
	}
	return 0
}

type borrowedDirectoryCache interface {
	prefetch(key, parentKey uint64, parentFD int, name string, expectedIno uint64) bool
	open(key uint64) (int, bool)
	forget(key uint64)
	clear()
}

type ownedDirectoryCache interface {
	borrowedDirectoryCache
	close()
}

// Export is one prepared or published child of a Hub.
type Export struct {
	Tag  string
	Path string
	RO   bool
	UID  *uint32
	GID  *uint32

	identity Identity
	hub      *Hub

	// Platform watcher capabilities are populated while the export root is
	// pinned. Only the matching platform backend interprets its field.
	watchRootFD     int     //nolint:unused // consumed by watcher_linux.go
	watchRootHandle uintptr //nolint:unused // consumed by watcher_windows.go
	coherence       *exportCoherence

	cacheMu        sync.RWMutex
	directoryCache ownedDirectoryCache
	exportState    exportstate.Owner
	policyDenied   atomic.Bool
	// namespace serializes guest-originated name mutations with the
	// lstat/open policy check. The host is trusted, but concurrent FUSE
	// requests must not swap a FIFO or device into place between those steps.
	namespace sync.Mutex
	// node is the platform backend's root node, presented at /<tag>.
	node  fs.InodeEmbedder
	inode *fs.Inode
	// release drops the platform backend's pinned host resources (root
	// FD or handle). It runs at most once, from finish.
	release  func()
	onFinish func(*Export)
	// finishDrain schedules final resource release behind the serving
	// owner's exclusive request gate. OnForget runs inside a FUSE request,
	// so it cannot synchronously upgrade that gate without deadlocking.
	finishDrain     func(func())
	finishScheduled atomic.Bool
	finishSchedule  sync.Once
	finishOne       sync.Once
}

// State reports the export lifecycle for the control plane and dashboard.
func (e *Export) State() ExportState {
	if e == nil {
		return ExportGone
	}
	return e.exportState.Phase()
}

// Identity returns the kernel-object identity pinned by this export.
func (e *Export) Identity() Identity {
	if e == nil {
		return Identity{}
	}
	return e.identity
}

// PolicyDenied reports that the active organization-policy generation has
// withheld this otherwise-live export.
func (e *Export) PolicyDenied() bool {
	return e != nil && e.policyDenied.Load()
}

// advanceState performs a validated monotonic transition. Repeated or stale
// transitions are harmless, which lets forced removal, OnForget, and owner
// shutdown race without regressing or skipping release phases.
func (e *Export) advanceState(next ExportState) bool {
	return e != nil && e.exportState.Transition(next)
}

func (e *Export) usable() bool {
	state := e.State()
	return !e.policyDenied.Load() && (state == ExportActive || state == ExportDraining)
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

func (e *Export) longCacheHealthy() bool {
	return e != nil && e.hub != nil && e.hub.notificationsReady.Load() &&
		e.coherence != nil && e.coherence.Healthy()
}

// finish is the OnForget path. It revokes new operations immediately, then
// schedules the actual root-capability release after every request which may
// already have passed its lifecycle check has drained.
func (e *Export) finish() {
	if e == nil {
		return
	}
	e.finishSchedule.Do(func() {
		e.finishScheduled.Store(true)
		e.advanceState(ExportRevoked)
		if e.finishDrain != nil {
			e.finishDrain(e.finishNow)
			return
		}
		e.finishNow()
	})
}

// finishNow releases the pinned root while the caller either owns the
// serving request writer gate or knows the export was never published.
func (e *Export) finishNow() {
	if e == nil {
		return
	}
	e.finishOne.Do(func() {
		e.advanceState(ExportRevoked)
		if e.coherence != nil {
			e.coherence.close()
		}
		if e.release != nil {
			e.release()
		}
		if e.onFinish != nil {
			e.onFinish(e)
		}
		e.advanceState(ExportGone)
	})
}

// Prepared is a fully validated export that has not entered the live
// namespace. Splitting preparation from publication lets the sandbox manager
// persist sandbox.json before making an infallible map swap. Publish and Swap
// consume it on success; Close releases it on failure.
type Prepared struct {
	preparedState preparedstate.Owner
	export        *Export
}

func (p *Prepared) acquire() (*Export, preparedstate.Lease, bool) {
	if p == nil {
		return nil, preparedstate.Lease{}, false
	}
	lease, ok := p.preparedState.Acquire()
	if !ok {
		return nil, preparedstate.Lease{}, false
	}
	return p.export, lease, true
}

func (p *Prepared) complete(lease preparedstate.Lease, consumed bool) {
	if p == nil {
		return
	}
	if consumed {
		p.export = nil
	}
	p.preparedState.Complete(lease, consumed)
}

// Close releases a prepared export that was never published. If publication
// is in flight, Close joins that attempt before deciding which owner must
// release the pinned root.
func (p *Prepared) Close() {
	if p == nil {
		return
	}
	leader, done := p.preparedState.BeginClose()
	if !leader {
		<-done
		return
	}
	defer p.preparedState.FinishClose()
	export := p.export
	p.export = nil
	if export != nil {
		export.finishNow()
	}
}

// Identity returns the candidate's pinned root identity.
func (p *Prepared) Identity() Identity {
	export, lease, ok := p.acquire()
	if !ok {
		return Identity{}
	}
	defer p.complete(lease, false)
	if export == nil {
		return Identity{}
	}
	return export.identity
}
