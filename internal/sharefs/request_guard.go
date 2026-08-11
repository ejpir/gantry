//go:build linux || darwin || windows

package sharefs

import (
	"fmt"
	"os"
	"sync/atomic"

	"github.com/ejpir/gantry/internal/fusewire"

	"github.com/hanwen/go-fuse/v2/fuse"
)

const maxLiveNodes = 64 << 10

type resourceReporter interface {
	GantryResourceUsage() (nodes, handles int)
}

// requestGuard applies host-capability limits at the share service itself, so
// direct and brokered transports have identical retention bounds. Once a
// guest exceeds either limit the filesystem fails closed for its remaining
// lifetime; Close later drains requests and releases every retained resource.
type requestGuard struct {
	reporter resourceReporter
	failed   atomic.Bool
}

func newRequestGuard() *requestGuard {
	return new(requestGuard)
}

func (g *requestGuard) setReporter(handler fusewire.Handler) {
	g.reporter, _ = handler.(resourceReporter)
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
	n, status := handler.HandleRequest(in, out)
	if g.reporter == nil {
		return n, status
	}
	nodes, handles := g.reporter.GantryResourceUsage()
	if nodes > maxLiveNodes || handles > shareHandleLimit() {
		if g.failed.CompareAndSwap(false, true) {
			fmt.Fprintf(os.Stderr, "sharefs: resource limit exceeded: nodes=%d/%d handles=%d/%d\n",
				nodes, maxLiveNodes, handles, shareHandleLimit())
		}
		return 0, fuse.EIO
	}
	return n, status
}
