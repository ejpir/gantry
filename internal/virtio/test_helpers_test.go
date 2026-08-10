package virtio

import (
	"io"
	"sync"
)

type testPacketConn struct {
	rx        chan []byte
	tx        chan []byte
	closed    chan struct{}
	closeOnce sync.Once
}

func (c *testPacketConn) Read(p []byte) (int, error) {
	select {
	case frame := <-c.rx:
		return copy(p, frame), nil
	case <-c.closed:
		return 0, io.ErrClosedPipe
	}
}

func (c *testPacketConn) Write(p []byte) (int, error) {
	c.tx <- append([]byte(nil), p...)
	return len(p), nil
}

func (c *testPacketConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}
