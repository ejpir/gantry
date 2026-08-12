//go:build linux || darwin

package sandbox

import (
	"fmt"
	"net"
	"os"
	"time"

	"github.com/ejpir/gantry/internal/fusewire"
	"github.com/ejpir/gantry/internal/sharefs"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/hanwen/go-fuse/v2/virtiofs"
)

// startShareVhost switches the existing authenticated share channel to
// setup-only vhost-user control. The backend then maps guest RAM and handles
// virtqueues directly; request and response payloads never traverse w.share.
func (w *vmmWorker) startShareVhost(hub *sharefs.Hub) error {
	if w == nil || w.share == nil {
		return fmt.Errorf("vhost share control unavailable")
	}
	if hub == nil {
		return fmt.Errorf("share hub unavailable")
	}
	if w.shareE != nil {
		return fmt.Errorf("share backend already started")
	}
	conn, ok := w.share.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("vhost share control is %T, want Unix connection", w.share)
	}
	w.shareE = make(chan error, 1)
	debug := os.Getenv("GANTRY_DEBUG_FS") != ""
	stats := newVhostShareStats()
	go w.monitorShareServe(func() error {
		return virtiofs.ServeConn(conn, func(in, out [][]byte) int {
			var started time.Time
			if stats != nil {
				started = time.Now()
			}
			n, status := hub.HandleRequest(in, out)
			if stats != nil {
				stats.observe(in, out, n, status, time.Since(started))
			}
			if len(out) == 0 {
				return 0
			}
			if status != fuse.OK {
				return fusewire.WriteError(in, out, status)
			}
			capacity := 0
			for _, part := range out {
				capacity += len(part)
			}
			if n < 0 || n > capacity {
				return fusewire.WriteError(in, out, fuse.EIO)
			}
			return n
		}, debug, func(sink func([]byte) fuse.Status) {
			if sink == nil {
				hub.SetNotificationSink(nil)
				return
			}
			hub.SetNotificationSink(func(message []byte) fuse.Status {
				if !fusewire.ValidNotification(message) {
					return fuse.EINVAL
				}
				return sink(message)
			})
		})
	}, "vhost share backend", false)
	return nil
}
