package workerproto

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows transfers connected sockets with WSADuplicateSocket. The sender
// serializes WSAProtocolInfo over the dedicated authenticated channel; only
// the target worker PID can reconstruct the socket described by that blob.
const FDTokenLen = 16

const (
	fdSendTimeout = 10 * time.Second
	fdRecvTimeout = 10 * time.Second
)

type processConn struct {
	net.Conn
	pid    uint32
	sendMu sync.Mutex
}

// ForProcess binds a descriptor channel to its only valid socket-transfer
// destination. It is called after the worker has been spawned and its PID is
// known.
func ForProcess(conn net.Conn, pid uint32) net.Conn {
	return &processConn{Conn: conn, pid: pid}
}

func SendFD(conn net.Conn, token [FDTokenLen]byte, file *os.File) error {
	pc, ok := conn.(*processConn)
	if !ok || pc.pid == 0 {
		return fmt.Errorf("workerproto: Windows socket transfer has no target process")
	}
	if file == nil {
		return fmt.Errorf("workerproto: cannot send a nil socket")
	}
	// WSADuplicateSocket requires the source socket to remain open until the
	// destination has reconstructed and materialized a process-local duplicate.
	// Serialize complete payload+ack transactions so concurrent forwards cannot
	// interleave.
	pc.sendMu.Lock()
	defer pc.sendMu.Unlock()
	var info windows.WSAProtocolInfo
	if err := windows.WSADuplicateSocket(windows.Handle(file.Fd()), pc.pid, &info); err != nil {
		return fmt.Errorf("workerproto: duplicate socket for PID %d: %w", pc.pid, err)
	}
	if err := validateWindowsSocketTransfer(&info); err != nil {
		return err
	}
	deadline := time.Now().Add(fdSendTimeout)
	if err := pc.SetDeadline(deadline); err != nil && !isWindowsPipeConn(pc.Conn) {
		return fmt.Errorf("workerproto: bound socket send: %w", err)
	}
	defer func() { _ = pc.SetDeadline(time.Time{}) }()
	payload := make([]byte, FDTokenLen+int(unsafe.Sizeof(info)))
	copy(payload, token[:])
	copy(payload[FDTokenLen:], unsafe.Slice((*byte)(unsafe.Pointer(&info)), int(unsafe.Sizeof(info))))
	if err := writeAll(pc, payload); err != nil {
		return fmt.Errorf("workerproto: send socket: %w", err)
	}
	var ack [FDTokenLen]byte
	if _, err := io.ReadFull(pc, ack[:]); err != nil {
		return fmt.Errorf("workerproto: socket reconstruction ack: %w", err)
	}
	if ack != token {
		return fmt.Errorf("workerproto: socket reconstruction ack token mismatch")
	}
	return nil
}

func isWindowsPipeConn(conn net.Conn) bool {
	_, ok := conn.(*windowsPipeConn)
	return ok
}

func RecvFD(conn net.Conn) ([FDTokenLen]byte, *os.File, error) {
	_ = conn.SetReadDeadline(time.Now().Add(fdRecvTimeout))
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()
	return recvFDMsg(conn)
}

func recvFDMsg(conn net.Conn) ([FDTokenLen]byte, *os.File, error) {
	var token [FDTokenLen]byte
	var info windows.WSAProtocolInfo
	payload := make([]byte, FDTokenLen+int(unsafe.Sizeof(info)))
	if _, err := io.ReadFull(conn, payload); err != nil {
		return token, nil, fmt.Errorf("workerproto: recv socket: %w", err)
	}
	copy(token[:], payload[:FDTokenLen])
	copy(unsafe.Slice((*byte)(unsafe.Pointer(&info)), int(unsafe.Sizeof(info))), payload[FDTokenLen:])
	if err := validateWindowsSocketTransfer(&info); err != nil {
		return token, nil, err
	}
	handle, err := windows.WSASocket(-1, -1, -1, &info, 0,
		windows.WSA_FLAG_OVERLAPPED|windows.WSA_FLAG_NO_HANDLE_INHERIT)
	if err != nil {
		return token, nil, fmt.Errorf("workerproto: reconstruct socket: %w", err)
	}
	file := os.NewFile(uintptr(handle), "workerproto-socket")
	if file == nil {
		_ = windows.Closesocket(handle)
		return token, nil, fmt.Errorf("workerproto: reconstructed invalid socket")
	}
	// A cross-process WSADuplicateSocket result is not safe to acknowledge
	// merely because WSASocket returned. In particular, an AppContainer may
	// not finish Go's getsockname-based net.FileConn import before the sender
	// closes its last source handle. Import the socket and materialize a fresh
	// process-local duplicate first; callers can then import the returned file
	// after the acknowledgement without depending on the source lifetime.
	file, err = materializeSocketFile(file)
	if err != nil {
		return token, nil, err
	}
	if err := conn.SetWriteDeadline(time.Now().Add(fdRecvTimeout)); err != nil && !isWindowsPipeConn(conn) {
		_ = file.Close()
		return token, nil, fmt.Errorf("workerproto: socket ack deadline: %w", err)
	}
	if err := writeAll(conn, token[:]); err != nil {
		_ = file.Close()
		return token, nil, fmt.Errorf("workerproto: socket reconstruction ack: %w", err)
	}
	_ = conn.SetWriteDeadline(time.Time{})
	return token, file, nil
}

func validateWindowsSocketTransfer(info *windows.WSAProtocolInfo) error {
	// Windows can reconstruct AF_UNIX sockets with WSADuplicateSocket, but the
	// resulting handle is not portable across supported Windows releases. It
	// may fail Go's getsockname-based import or stop carrying data when the
	// source closes, depending on the host release. Production keeps
	// AF_UNIX path authority in the supervisor and transfers one end of a TCP
	// relay instead; fail closed if another caller bypasses that boundary.
	if info.AddressFamily == windows.AF_UNIX {
		return fmt.Errorf("workerproto: Windows AF_UNIX sockets require a supervisor-owned relay")
	}
	return nil
}

func materializeSocketFile(file *os.File) (*os.File, error) {
	remote, err := net.FileConn(file)
	_ = file.Close()
	if err != nil {
		return nil, fmt.Errorf("workerproto: import reconstructed socket: %w", err)
	}
	consumer, relay, err := windowsLoopbackPair()
	if err != nil {
		_ = remote.Close()
		return nil, err
	}
	materialized, err := consumer.File()
	_ = consumer.Close()
	if err != nil {
		_ = relay.Close()
		_ = remote.Close()
		return nil, fmt.Errorf("workerproto: materialize local relay socket: %w", err)
	}
	// A WSADuplicateSocket reconstruction can become unusable after the source
	// process closes its final handle even though the initial import succeeded.
	// Keep that socket inside this process and hand callers a freshly-created
	// local TCP endpoint; the relay owns both unstable handles until EOF.
	go relayWindowsSocket(remote, relay)
	return materialized, nil
}

func windowsLoopbackPair() (a, b *net.TCPConn, resultErr error) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, nil, fmt.Errorf("workerproto: local relay listen: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, listener.Close()) }()
	dialed, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		return nil, nil, fmt.Errorf("workerproto: local relay dial: %w", err)
	}
	accepted, err := listener.AcceptTCP()
	if err != nil {
		_ = dialed.Close()
		return nil, nil, fmt.Errorf("workerproto: local relay accept: %w", err)
	}
	return accepted, dialed, nil
}

func relayWindowsSocket(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	copyOne := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if closeWriter, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = closeWriter.CloseWrite()
		}
	}
	go copyOne(a, b)
	go copyOne(b, a)
	wg.Wait()
	_ = a.Close()
	_ = b.Close()
}

func writeAll(conn net.Conn, data []byte) error {
	for len(data) != 0 {
		n, err := conn.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrUnexpectedEOF
		}
		data = data[n:]
	}
	return nil
}

type FDMux struct {
	conn      net.Conn
	mu        sync.Mutex
	pending   map[[FDTokenLen]byte]*FDWait
	unclaimed map[[FDTokenLen]byte]*os.File
	canceled  map[[FDTokenLen]byte]time.Time
	stickyEr  error
	done      chan struct{}
	doneOnce  sync.Once
	closeOnce sync.Once
	closeErr  error
}

const fdUnclaimedMax = 64
const fdCanceledMax = 64

type FDResult struct {
	F   *os.File
	Err error
}

type FDWait struct {
	mux       *FDMux
	token     [FDTokenLen]byte
	result    chan FDResult
	finishOne sync.Once
}

func NewFDMux(conn net.Conn) *FDMux {
	m := &FDMux{
		conn: conn, pending: map[[FDTokenLen]byte]*FDWait{},
		unclaimed: map[[FDTokenLen]byte]*os.File{},
		canceled:  map[[FDTokenLen]byte]time.Time{}, done: make(chan struct{}),
	}
	go m.loop()
	return m
}

func (m *FDMux) fail(err error) {
	m.doneOnce.Do(func() {
		m.mu.Lock()
		m.stickyEr = err
		pending, unclaimed := m.pending, m.unclaimed
		m.pending = map[[FDTokenLen]byte]*FDWait{}
		m.unclaimed = map[[FDTokenLen]byte]*os.File{}
		m.canceled = map[[FDTokenLen]byte]time.Time{}
		m.mu.Unlock()
		for _, file := range unclaimed {
			_ = file.Close()
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
		token, file, err := recvFDMsg(m.conn)
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
			case wait.result <- FDResult{F: file}:
				file = nil
			default:
			}
		case m.unclaimed[token] != nil:
		case len(m.unclaimed) < fdUnclaimedMax:
			m.unclaimed[token] = file
			file = nil
		}
		m.mu.Unlock()
		if file != nil {
			_ = file.Close()
		}
	}
}

func (m *FDMux) Expect(token [FDTokenLen]byte) (*FDWait, error) {
	wait := &FDWait{mux: m, token: token, result: make(chan FDResult, 1)}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stickyEr != nil {
		return nil, m.stickyEr
	}
	delete(m.canceled, token)
	if m.pending[token] != nil {
		return nil, fmt.Errorf("workerproto: duplicate socket expectation")
	}
	m.pending[token] = wait
	if file, ok := m.unclaimed[token]; ok {
		delete(m.unclaimed, token)
		wait.result <- FDResult{F: file}
	}
	return wait, nil
}

func (w *FDWait) Cancel() {
	w.finishOne.Do(func() {
		w.mux.mu.Lock()
		w.mux.cancelLocked(w.token, w)
		w.mux.mu.Unlock()
	})
}

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
		return nil, fmt.Errorf("workerproto: socket for token never arrived")
	}
}

func (m *FDMux) Recv(token [FDTokenLen]byte) (*os.File, error) {
	wait, err := m.Expect(token)
	if err != nil {
		return nil, err
	}
	return wait.Wait(fdRecvTimeout)
}
