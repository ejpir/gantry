package manager

import (
	"net"
	"sync"

	"github.com/ejpir/gantry/internal/sandbox/localsec"
)

// limitedListener bounds concurrent connections and optionally restricts
// accepted peers to the same account (unix sockets; TLS peers authenticate
// at the HTTP layer instead).
type limitedListener struct {
	net.Listener
	slots        chan struct{}
	sameUserOnly bool
}

func (l *limitedListener) Accept() (net.Conn, error) {
	for {
		connection, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if l.sameUserOnly && !localsec.PeerSameUser(connection) {
			_ = connection.Close()
			continue
		}
		if !tryAcquireSlot(l.slots) {
			_ = connection.Close()
			continue
		}
		return &managerCountedConn{Conn: connection, release: func() { releaseSlot(l.slots) }}, nil
	}
}

type managerCountedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *managerCountedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}
