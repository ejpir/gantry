package sharefs

import (
	"github.com/ejpir/gantry/internal/fusewire"
	"github.com/hanwen/go-fuse/v2/fuse"
)

// BorrowedHub is the non-owning virtio-fs capability shared with VMM and
// supervisor services. It deliberately omits Close; only the ShareManager
// which owns the underlying Hub may release it.
type BorrowedHub interface {
	Prepare(tag, path string, readOnly bool) (*Prepared, string, error)
	Publish(*Prepared) (*Export, error)
	Remove(tag string, force bool) (*Export, error)
	HandleRequest(in, out [][]byte) (int, fuse.Status)
	SetNotificationSink(fusewire.NotificationSink)
}

type borrowedHub struct{ hub *Hub }

func Borrow(hub *Hub) BorrowedHub {
	if hub == nil {
		return nil
	}
	return borrowedHub{hub: hub}
}

func (h borrowedHub) Prepare(tag, path string, readOnly bool) (*Prepared, string, error) {
	return h.hub.Prepare(tag, path, readOnly)
}
func (h borrowedHub) Publish(prepared *Prepared) (*Export, error) {
	return h.hub.Publish(prepared)
}
func (h borrowedHub) Remove(tag string, force bool) (*Export, error) {
	return h.hub.Remove(tag, force)
}
func (h borrowedHub) HandleRequest(in, out [][]byte) (int, fuse.Status) {
	return h.hub.HandleRequest(in, out)
}
func (h borrowedHub) SetNotificationSink(sink fusewire.NotificationSink) {
	h.hub.SetNotificationSink(sink)
}
