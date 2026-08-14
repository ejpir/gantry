//go:build linux || darwin || windows

package sharefs

import (
	"encoding/binary"
	"fmt"
	"os"
	"sync/atomic"

	"github.com/ejpir/gantry/internal/fusewire"

	"github.com/hanwen/go-fuse/v2/fuse"
)

const (
	maxLiveNodes      = 64 << 10
	resourcePruneSize = (fusewire.MaxNotificationBytes - 16 - 16) / 8
	pruneNodeMark     = maxLiveNodes - resourcePruneSize
)

type resourceReporter interface {
	GantryResourceUsage() (nodes, handles int)
}

type resourcePruner interface {
	GantryPruneResources(limit int) fuse.Status
}

// requestGuard applies host-capability limits at the share service itself, so
// direct and brokered transports have identical retention bounds. Cache and
// handle pressure backpressures only operations that retain more resources;
// existing operations, FORGET, and RELEASE remain available for recovery.
// A contained backend panic still fails the filesystem closed.
type requestGuard struct {
	reporter       resourceReporter
	pruner         resourcePruner
	failed         atomic.Bool
	pressureLogged atomic.Bool
	prunedAt       atomic.Int64
}

func newRequestGuard() *requestGuard {
	return new(requestGuard)
}

func (g *requestGuard) setReporter(handler fusewire.Handler) {
	g.reporter, _ = handler.(resourceReporter)
	g.pruner, _ = handler.(resourcePruner)
}

func (g *requestGuard) containPanic(value any) fuse.Status {
	g.fail(fmt.Errorf("contained filesystem panic (%T): %v", value, value))
	return fuse.EIO
}

func (g *requestGuard) fail(err error) {
	if g != nil && g.failed.CompareAndSwap(false, true) {
		fmt.Fprintf(os.Stderr, "sharefs: %v\n", err)
	}
}

func (g *requestGuard) handle(handler fusewire.Handler, in, out [][]byte) (int, fuse.Status) {
	if g == nil {
		return handler.HandleRequest(in, out)
	}
	if g.failed.Load() {
		return 0, fuse.EIO
	}
	if g.reporter != nil {
		nodes, handles := g.reporter.GantryResourceUsage()
		g.maintainNodeBudget(nodes)
		op := requestOpcode(in)
		if nodes >= maxLiveNodes && retainsNode(op) {
			g.logPressure(nodes, handles)
			return 0, fuse.EAGAIN
		}
		if handles >= shareHandleLimit() && retainsHandle(op) {
			g.logPressure(nodes, handles)
			return 0, fuse.EMFILE
		}
	}
	n, status := handler.HandleRequest(in, out)
	if g.reporter == nil {
		return n, status
	}
	nodes, handles := g.reporter.GantryResourceUsage()
	g.maintainNodeBudget(nodes)
	if nodes >= maxLiveNodes || handles >= shareHandleLimit() {
		g.logPressure(nodes, handles)
	} else {
		g.pressureLogged.Store(false)
	}
	return n, status
}

func (g *requestGuard) maintainNodeBudget(nodes int) {
	if nodes < pruneNodeMark {
		g.prunedAt.Store(0)
		return
	}
	if g.pruner == nil || g.prunedAt.Load() < 0 {
		return
	}
	previous := g.prunedAt.Load()
	if previous > 0 && nodes >= int(previous) && nodes < int(previous)+resourcePruneSize {
		return
	}
	status := g.pruner.GantryPruneResources(resourcePruneSize)
	switch status {
	case fuse.OK:
		g.prunedAt.Store(int64(nodes))
	case fuse.ENOSYS:
		g.prunedAt.Store(-1)
	}
}

func (g *requestGuard) logPressure(nodes, handles int) {
	if g.pressureLogged.CompareAndSwap(false, true) {
		fmt.Fprintf(os.Stderr, "sharefs: resource watermark reached: nodes=%d/%d handles=%d/%d; new allocations temporarily backpressured\n",
			nodes, maxLiveNodes, handles, shareHandleLimit())
	}
}

func requestOpcode(in [][]byte) uint32 {
	var prefix [8]byte
	if fusewire.CopyPrefix(prefix[:], in) != len(prefix) {
		return 0
	}
	return binary.LittleEndian.Uint32(prefix[4:8])
}

func retainsNode(op uint32) bool {
	switch op {
	case fuse.OpLookup, fuse.OpMknod, fuse.OpMkdir, fuse.OpSymlink,
		fuse.OpLink, fuse.OpCreate, fuse.OpReaddirplus, fuse.OpTmpfile:
		return true
	default:
		return false
	}
}

func retainsHandle(op uint32) bool {
	switch op {
	case fuse.OpOpen, fuse.OpOpendir, fuse.OpCreate, fuse.OpTmpfile:
		return true
	default:
		return false
	}
}
