//go:build linux || darwin || windows

package vmmworker

import (
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"

	"github.com/ejpir/gantry/internal/diskbroker"
	"github.com/ejpir/gantry/internal/sandbox/worker"
)

// diskRelay retains one fixed-size writable image in the trusted supervisor.
// The VMM worker receives only peer, so even arbitrary worker code cannot grow
// or write the host file outside the broker's original bounds.
type diskRelay struct {
	conn net.Conn
	disk *os.File
	done chan struct{}

	mu       sync.Mutex
	err      error
	closing  atomic.Bool
	closeOne sync.Once
	closeErr error
}

func newDiskRelay(source *os.File, size uint64) (*diskRelay, net.Conn, error) {
	if source == nil || size == 0 {
		return nil, nil, fmt.Errorf("disk relay: invalid source or size")
	}
	duplicate, err := duplicateDiskFile(source)
	if err != nil {
		return nil, nil, err
	}
	supervisor, peer, err := worker.SocketpairConns()
	if err != nil {
		_ = duplicate.Close()
		return nil, nil, err
	}
	relay := &diskRelay{conn: supervisor, disk: duplicate, done: make(chan struct{})}
	go relay.serve(size)
	return relay, peer, nil
}

func (relay *diskRelay) serve(size uint64) {
	err := diskbroker.Serve(relay.conn, relay.disk, size)
	_ = relay.conn.Close()
	if syncErr := relay.disk.Sync(); syncErr != nil {
		err = errors.Join(err, fmt.Errorf("sync brokered writable disk: %w", syncErr))
	}
	if closeErr := relay.disk.Close(); closeErr != nil {
		err = errors.Join(err, fmt.Errorf("close brokered writable disk: %w", closeErr))
	}
	relay.mu.Lock()
	relay.err = err
	relay.mu.Unlock()
	close(relay.done)
}

func (relay *diskRelay) Close() error {
	relay.closing.Store(true)
	relay.closeOne.Do(func() {
		relay.closeErr = relay.conn.Close()
		<-relay.done
	})
	if errors.Is(relay.closeErr, net.ErrClosed) {
		return nil
	}
	return relay.closeErr
}

func (relay *diskRelay) Err() error {
	<-relay.done
	relay.mu.Lock()
	defer relay.mu.Unlock()
	return relay.err
}

func (relay *diskRelay) Done() <-chan struct{} { return relay.done }
func (relay *diskRelay) ExpectedClose() bool   { return relay.closing.Load() }
