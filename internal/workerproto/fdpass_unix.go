//go:build linux || darwin

package workerproto

import (
	"fmt"
	"net"
	"os"
	"sync"
	"syscall"
	"time"
)

// FD passing over a dedicated unix channel (SCM_RIGHTS). Runtime
// descriptor transfers — vsock dial bridging, share hot-add — correlate
// an RPC on the control channel with a descriptor on this one via a
// random token: the supervisor sends the descriptor with the token,
// the RPC handler waits for the matching token. Keeping transfers on
// their own channel means every message here is exactly one sendmsg
// with a fixed-size payload, so stream framing never splits or
// coalesces the rights-carrying byte range.
//
// Layout per message: FDTokenLen payload bytes (the token) + one fd.

// FDTokenLen is the byte length of a transfer token.
const FDTokenLen = 16

// fdRecvTimeout bounds one descriptor receive; the peer sends the fd
// immediately around the correlated RPC, so a longer wait is a bug.
const fdRecvTimeout = 10 * time.Second

// SendFD transfers fd with its correlation token in a single sendmsg.
func SendFD(conn net.Conn, token [FDTokenLen]byte, f *os.File) error {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("workerproto: fd passing needs a unix channel, got %T", conn)
	}
	oob := syscall.UnixRights(int(f.Fd()))
	if _, _, err := uc.WriteMsgUnix(token[:], oob, nil); err != nil {
		return fmt.Errorf("workerproto: send fd: %w", err)
	}
	return nil
}

// RecvFD receives one token + descriptor. The descriptor is already
// duplicated into this process by the kernel; it is independent of the
// sender's copy except for sharing the open file description (offset,
// locks) — which is exactly what the vsock bridge and share pinning
// rely on.
func RecvFD(conn net.Conn) ([FDTokenLen]byte, *os.File, error) {
	var token [FDTokenLen]byte
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return token, nil, fmt.Errorf("workerproto: fd passing needs a unix channel, got %T", conn)
	}
	_ = uc.SetReadDeadline(time.Now().Add(fdRecvTimeout))
	defer func() { _ = uc.SetReadDeadline(time.Time{}) }()
	oob := make([]byte, syscall.CmsgSpace(4))
	_, oobn, _, _, err := uc.ReadMsgUnix(token[:], oob)
	if err != nil {
		return token, nil, fmt.Errorf("workerproto: recv fd: %w", err)
	}
	cmsgs, err := syscall.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return token, nil, fmt.Errorf("workerproto: parse rights: %w", err)
	}
	for i := range cmsgs {
		fds, err := syscall.ParseUnixRights(&cmsgs[i])
		if err != nil {
			continue
		}
		if len(fds) > 0 {
			f := os.NewFile(uintptr(fds[0]), "workerproto-fd")
			for _, extra := range fds[1:] {
				_ = syscall.Close(extra)
			}
			return token, f, nil
		}
	}
	return token, nil, fmt.Errorf("workerproto: no descriptor in message")
}

// FDMux receives token-correlated descriptors on behalf of many
// concurrent waiters: one receive loop dispatches by token, so two
// racing vsock dial-backs can never steal each other's descriptor.
// Unknown tokens are closed and dropped (a supervisor bug, but never a
// stall). On transport error every waiter fails.
type FDMux struct {
	conn      net.Conn
	mu        sync.Mutex
	pending   map[[FDTokenLen]byte]chan FDResult
	unclaimed map[[FDTokenLen]byte]*os.File // arrived before the RPC (parked)
	stickyEr  error
	done      chan struct{}
	doneOnce  sync.Once
}

// fdUnclaimedMax bounds parked descriptors: transfers normally pair with
// an RPC within milliseconds, so a flood of unmatched fds is a peer bug —
// excess is closed and dropped rather than grown without bound.
const fdUnclaimedMax = 64

// FDResult is one dispatched descriptor transfer.
type FDResult struct {
	F   *os.File
	Err error
}

// NewFDMux starts the receive loop on conn (a dedicated fd channel).
func NewFDMux(conn net.Conn) *FDMux {
	m := &FDMux{conn: conn, pending: map[[FDTokenLen]byte]chan FDResult{}, unclaimed: map[[FDTokenLen]byte]*os.File{}, done: make(chan struct{})}
	go m.loop()
	return m
}

func (m *FDMux) fail(err error) {
	m.doneOnce.Do(func() {
		m.mu.Lock()
		m.stickyEr = err
		pending := m.pending
		m.pending = map[[FDTokenLen]byte]chan FDResult{}
		m.mu.Unlock()
		for _, ch := range pending {
			ch <- FDResult{Err: err}
		}
		close(m.done)
	})
}

func (m *FDMux) loop() {
	for {
		token, f, err := RecvFD(m.conn)
		if err != nil {
			m.fail(err)
			return
		}
		m.mu.Lock()
		ch, ok := m.pending[token]
		if ok {
			delete(m.pending, token)
		} else if len(m.unclaimed) < fdUnclaimedMax {
			// The descriptor beat the RPC that names it (the peer sends
			// the fd before its call completes): park it for Expect.
			m.unclaimed[token] = f
			f = nil
		} else {
			_ = f.Close() // flood of unmatched tokens: bounded drop
		}
		m.mu.Unlock()
		if ok {
			ch <- FDResult{F: f}
		}
	}
}

// Expect registers interest in token BEFORE the correlated RPC is sent
// (the peer may transfer the descriptor before answering the RPC; a
// post-RPC Recv could deadlock against a sender waiting on the receive).
// Cancel unregisters without receiving.
func (m *FDMux) Expect(token [FDTokenLen]byte) (<-chan FDResult, error) {
	ch := make(chan FDResult, 1)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stickyEr != nil {
		return nil, m.stickyEr
	}
	if f, ok := m.unclaimed[token]; ok {
		// The descriptor arrived before we registered (RPC ordering).
		delete(m.unclaimed, token)
		ch <- FDResult{F: f}
		return ch, nil
	}
	if m.pending[token] != nil {
		return nil, fmt.Errorf("workerproto: duplicate fd expectation")
	}
	m.pending[token] = ch
	return ch, nil
}

// Cancel drops a registration made by Expect (RPC failed before transfer).
func (m *FDMux) Cancel(token [FDTokenLen]byte) {
	m.mu.Lock()
	delete(m.pending, token)
	m.mu.Unlock()
}

// Recv waits (bounded) for the descriptor carrying token.
func (m *FDMux) Recv(token [FDTokenLen]byte) (*os.File, error) {
	ch, err := m.Expect(token)
	if err != nil {
		return nil, err
	}
	timer := time.NewTimer(fdRecvTimeout)
	defer timer.Stop()
	select {
	case r := <-ch:
		return r.F, r.Err
	case <-timer.C:
		m.Cancel(token)
		return nil, fmt.Errorf("workerproto: fd for token never arrived")
	}
}
