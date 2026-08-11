package virtiofs

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/hanwen/go-fuse/v2/internal/vhostuser"
)

// ServeFS connects a FUSE filesystem to a virtio-fs device over a vhost-user
// socket.
//
// ServeConn runs a vhost-user virtio-fs backend on an already-authenticated
// Unix connection. Request and response buffers point directly into the
// shared guest-memory regions registered by the frontend. Gantry's optional
// notification setter is attached only after the owned guest driver has
// populated its negotiated third virtqueue.
func ServeConn(conn *net.UnixConn, handle func(read, write [][]byte) int, debug bool, setNotifications ...func(func([]byte) fuse.Status)) error {
	if conn == nil || handle == nil {
		return fmt.Errorf("virtiofs: nil vhost connection or handler")
	}
	if len(setNotifications) > 1 {
		return fmt.Errorf("virtiofs: multiple notification setters")
	}
	queueCount := 2
	if len(setNotifications) == 1 && setNotifications[0] != nil {
		queueCount = 3
	}
	dev := vhostuser.NewDeviceWithQueues(queueCount, func(vqe *vhostuser.VirtqElem) int {
		return handle(vqe.Read, vqe.Write)
	})
	if queueCount == 3 {
		setter := setNotifications[0]
		if err := dev.SetNotificationQueue(2, func(sink func([]byte) syscall.Errno) {
			if sink == nil {
				setter(nil)
				return
			}
			setter(func(message []byte) fuse.Status { return fuse.Status(sink(message)) })
		}); err != nil {
			return err
		}
	}
	dev.Debug = debug
	srv := vhostuser.NewServer(conn, dev)
	srv.Debug = debug
	defer func() { _ = srv.Close() }()
	err := srv.Serve()
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func ServeFS(sockpath string, rawFS fuse.RawFileSystem, opts *fuse.MountOptions) {
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: sockpath, Net: "unix"})
	if err != nil {
		log.Fatal("Listen", err)
	}

	opts.DisableSplice = true
	ps := fuse.NewProtocolServer(rawFS, opts)
	for {
		conn, err := l.AcceptUnix()
		if err != nil {
			break
		}

		if err := ServeConn(conn, func(read, write [][]byte) int {
			n, _ := ps.HandleRequest(read, write)
			return n
		}, true); err != nil {
			log.Printf("Serve: %v %T", err, err)
		}
	}
}
