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

const (
	// Descriptor transfer surrounds a correlated RPC; a peer that does not
	// consume it must not pin a supervisor handler and descriptor forever.
	fdSendTimeout = 10 * time.Second
	fdRecvTimeout = 10 * time.Second
)

// InheritedConn duplicates an inherited descriptor into a pollable net.Conn
// and closes the original descriptor. Worker command entry points use it to
// reconstruct their fixed bootstrap channel tables after re-exec.
func InheritedConn(fd uintptr, name string) (net.Conn, error) {
	f := os.NewFile(fd, name)
	if f == nil {
		return nil, fmt.Errorf("inherited %s fd %d unavailable", name, fd)
	}
	defer func() { _ = f.Close() }()
	c, err := net.FileConn(f)
	if err != nil {
		return nil, fmt.Errorf("inherited %s fd %d: %w", name, fd, err)
	}
	return c, nil
}

// SendFD transfers fd with its correlation token in a single sendmsg.
func SendFD(conn net.Conn, token [FDTokenLen]byte, f *os.File) error {
	return sendFDWithTimeout(conn, token, f, fdSendTimeout)
}

func sendFDWithTimeout(conn net.Conn, token [FDTokenLen]byte, f *os.File, timeout time.Duration) error {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("workerproto: fd passing needs a unix channel, got %T", conn)
	}
	if f == nil {
		return fmt.Errorf("workerproto: cannot send a nil descriptor")
	}
	if err := uc.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return fmt.Errorf("workerproto: bound fd send: %w", err)
	}
	defer func() { _ = uc.SetWriteDeadline(time.Time{}) }()
	oob := syscall.UnixRights(int(f.Fd()))
	n, oobn, err := uc.WriteMsgUnix(token[:], oob, nil)
	if err != nil {
		return fmt.Errorf("workerproto: send fd: %w", err)
	}
	if n != len(token) || oobn != len(oob) {
		return fmt.Errorf("workerproto: short fd message: payload %d/%d, control %d/%d", n, len(token), oobn, len(oob))
	}
	return nil
}

// RecvFD receives one descriptor with its correlation token, bounded by
// fdRecvTimeout. The kernel duplicates the descriptor into this process;
// sender and receiver share only its underlying open-file description.
func RecvFD(conn net.Conn) ([FDTokenLen]byte, *os.File, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return [FDTokenLen]byte{}, nil, fmt.Errorf("workerproto: fd passing needs a unix channel, got %T", conn)
	}
	_ = uc.SetReadDeadline(time.Now().Add(fdRecvTimeout))
	defer func() { _ = uc.SetReadDeadline(time.Time{}) }()
	return recvFDMsg(conn)
}

// recvFDMsg receives one descriptor with its correlation token and NO
// deadline: the FDMux loop idles on it for the worker's whole lifetime,
// so a bounded read here kills every transfer that arrives more than
// fdRecvTimeout after boot (first observed on macOS: share add and exec
// failed minutes in with the loop's sticky i/o timeout).
func recvFDMsg(conn net.Conn) ([FDTokenLen]byte, *os.File, error) {
	var token [FDTokenLen]byte
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return token, nil, fmt.Errorf("workerproto: fd passing needs a unix channel, got %T", conn)
	}
	oob := make([]byte, syscall.CmsgSpace(4))
	n, oobn, flags, _, err := uc.ReadMsgUnix(token[:], oob)
	if err != nil {
		return token, nil, fmt.Errorf("workerproto: recv fd: %w", err)
	}
	cmsgs, err := syscall.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return token, nil, fmt.Errorf("workerproto: parse rights: %w", err)
	}
	var fds []int
	validControl := len(cmsgs) == 1
	for i := range cmsgs {
		if cmsgs[i].Header.Level != syscall.SOL_SOCKET || cmsgs[i].Header.Type != syscall.SCM_RIGHTS {
			validControl = false
			continue
		}
		rights, rightsErr := syscall.ParseUnixRights(&cmsgs[i])
		if rightsErr != nil {
			validControl = false
			continue
		}
		fds = append(fds, rights...)
	}
	valid := n == FDTokenLen && flags&(syscall.MSG_TRUNC|syscall.MSG_CTRUNC) == 0 && validControl && len(fds) == 1
	if !valid {
		for _, fd := range fds {
			_ = syscall.Close(fd)
		}
		return token, nil, fmt.Errorf("workerproto: malformed fd message: payload=%d control=%d flags=%#x descriptors=%d", n, oobn, flags, len(fds))
	}
	f := os.NewFile(uintptr(fds[0]), "workerproto-fd")
	if f == nil {
		_ = syscall.Close(fds[0])
		return token, nil, fmt.Errorf("workerproto: received invalid descriptor")
	}
	return token, f, nil
}

// FDMux receives token-correlated descriptors on behalf of many
// concurrent waiters: one receive loop dispatches by token, so two
// racing vsock dial-backs can never steal each other's descriptor.
// Descriptors that beat their RPC are parked under a strict bound; duplicates,
// canceled transfers, and overflow are closed. On transport error every waiter
// fails and every descriptor still owned by the mux is released.
type FDMux struct {
	conn      net.Conn
	mu        sync.Mutex
	pending   map[[FDTokenLen]byte]*FDWait
	unclaimed map[[FDTokenLen]byte]*os.File // arrived before the RPC (parked)
	canceled  map[[FDTokenLen]byte]time.Time
	stickyEr  error
	done      chan struct{}
	doneOnce  sync.Once
	closeOnce sync.Once
	closeErr  error
}

// fdUnclaimedMax bounds parked descriptors: transfers normally pair with
// an RPC within milliseconds, so a flood of unmatched fds is a peer bug —
// excess is closed and dropped rather than grown without bound.
const fdUnclaimedMax = 64
const fdCanceledMax = 64

// FDResult is one dispatched descriptor transfer.
type FDResult struct {
	F   *os.File
	Err error
}

// FDWait owns one expectation until Wait or Cancel completes it. Keeping the
// registration alive after dispatch lets Cancel close a descriptor that won
// the race with a failed RPC instead of abandoning it in a buffered channel.
type FDWait struct {
	mux       *FDMux
	token     [FDTokenLen]byte
	result    chan FDResult
	finishOne sync.Once
}

// NewFDMux starts the receive loop on conn (a dedicated fd channel).
func NewFDMux(conn net.Conn) *FDMux {
	m := &FDMux{
		conn:      conn,
		pending:   map[[FDTokenLen]byte]*FDWait{},
		unclaimed: map[[FDTokenLen]byte]*os.File{},
		canceled:  map[[FDTokenLen]byte]time.Time{},
		done:      make(chan struct{}),
	}
	go m.loop()
	return m
}

func (m *FDMux) fail(err error) {
	m.doneOnce.Do(func() {
		m.mu.Lock()
		m.stickyEr = err
		pending := m.pending
		unclaimed := m.unclaimed
		m.pending = map[[FDTokenLen]byte]*FDWait{}
		m.unclaimed = map[[FDTokenLen]byte]*os.File{}
		m.canceled = map[[FDTokenLen]byte]time.Time{}
		m.mu.Unlock()
		for _, f := range unclaimed {
			_ = f.Close()
		}
		for _, wait := range pending {
			select {
			case result := <-wait.result:
				if result.F != nil {
					_ = result.F.Close()
				}
			default:
			}
			wait.result <- FDResult{Err: err}
		}
		close(m.done)
	})
}

// Close terminates the relationship and releases every descriptor owned by
// the mux. It is idempotent; waiters receive the same terminal error as a peer
// disconnect.
func (m *FDMux) Close() error {
	m.closeOnce.Do(func() {
		m.closeErr = m.conn.Close()
		m.fail(net.ErrClosed)
	})
	return m.closeErr
}

func (m *FDMux) pruneCanceledLocked(now time.Time) {
	for token, deadline := range m.canceled {
		if !now.Before(deadline) {
			delete(m.canceled, token)
		}
	}
}

func (m *FDMux) cancelLocked(token [FDTokenLen]byte, wait *FDWait) {
	if current := m.pending[token]; current == wait {
		delete(m.pending, token)
	}
	select {
	case result := <-wait.result:
		if result.F != nil {
			_ = result.F.Close()
		}
	default:
	}
	now := time.Now()
	m.pruneCanceledLocked(now)
	if len(m.canceled) >= fdCanceledMax {
		for old := range m.canceled {
			delete(m.canceled, old)
			break
		}
	}
	m.canceled[token] = now.Add(fdRecvTimeout)
}

func (m *FDMux) loop() {
	for {
		token, f, err := recvFDMsg(m.conn)
		if err != nil {
			m.fail(err)
			return
		}
		m.mu.Lock()
		m.pruneCanceledLocked(time.Now())
		wait, expected := m.pending[token]
		_, canceled := m.canceled[token]
		switch {
		case canceled:
			delete(m.canceled, token)
		case expected:
			select {
			case wait.result <- FDResult{F: f}:
				f = nil
			default:
				// A second descriptor for one token is a protocol error. The
				// first result remains authoritative; close the duplicate.
			}
		case m.unclaimed[token] != nil:
			// Preserve the first arrival for a token and close duplicates.
		case len(m.unclaimed) < fdUnclaimedMax:
			// The descriptor beat the RPC that names it (the peer sends
			// the fd before its call completes): park it for Expect.
			m.unclaimed[token] = f
			f = nil
		}
		m.mu.Unlock()
		if f != nil {
			_ = f.Close()
		}
	}
}

// Expect registers interest in token BEFORE the correlated RPC is sent
// (the peer may transfer the descriptor before answering the RPC; a
// post-RPC Recv could deadlock against a sender waiting on the receive).
// The returned FDWait must be completed with Wait or Cancel.
func (m *FDMux) Expect(token [FDTokenLen]byte) (*FDWait, error) {
	wait := &FDWait{mux: m, token: token, result: make(chan FDResult, 1)}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stickyEr != nil {
		return nil, m.stickyEr
	}
	delete(m.canceled, token) // an explicit new expectation permits token reuse
	if m.pending[token] != nil {
		return nil, fmt.Errorf("workerproto: duplicate fd expectation")
	}
	m.pending[token] = wait
	if f, ok := m.unclaimed[token]; ok {
		// The descriptor arrived before we registered (RPC ordering).
		delete(m.unclaimed, token)
		wait.result <- FDResult{F: f}
	}
	return wait, nil
}

// Cancel drops an expectation and closes a descriptor that arrived before the
// correlated RPC failed. A short-lived tombstone closes a late arrival too.
func (w *FDWait) Cancel() {
	w.finishOne.Do(func() {
		w.mux.mu.Lock()
		w.mux.cancelLocked(w.token, w)
		w.mux.mu.Unlock()
	})
}

// Wait receives the expected descriptor or cancels the expectation at the
// deadline. Ownership of a non-nil result transfers to the caller.
func (w *FDWait) Wait(timeout time.Duration) (*os.File, error) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case result := <-w.result:
		w.finishOne.Do(func() {
			w.mux.mu.Lock()
			if current := w.mux.pending[w.token]; current == w {
				delete(w.mux.pending, w.token)
			}
			w.mux.mu.Unlock()
		})
		return result.F, result.Err
	case <-timer.C:
		w.Cancel()
		return nil, fmt.Errorf("workerproto: fd for token never arrived")
	}
}

// Recv waits (bounded) for the descriptor carrying token.
func (m *FDMux) Recv(token [FDTokenLen]byte) (*os.File, error) {
	wait, err := m.Expect(token)
	if err != nil {
		return nil, err
	}
	return wait.Wait(fdRecvTimeout)
}
