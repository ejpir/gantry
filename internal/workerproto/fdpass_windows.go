package workerproto

import (
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
	pid uint32
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
	var info windows.WSAProtocolInfo
	if err := windows.WSADuplicateSocket(windows.Handle(file.Fd()), pc.pid, &info); err != nil {
		return fmt.Errorf("workerproto: duplicate socket for PID %d: %w", pc.pid, err)
	}
	if err := pc.SetWriteDeadline(time.Now().Add(fdSendTimeout)); err != nil && !isWindowsPipeConn(pc.Conn) {
		return fmt.Errorf("workerproto: bound socket send: %w", err)
	}
	defer func() { _ = pc.SetWriteDeadline(time.Time{}) }()
	payload := make([]byte, FDTokenLen+int(unsafe.Sizeof(info)))
	copy(payload, token[:])
	copy(payload[FDTokenLen:], unsafe.Slice((*byte)(unsafe.Pointer(&info)), int(unsafe.Sizeof(info))))
	if err := writeAll(pc, payload); err != nil {
		return fmt.Errorf("workerproto: send socket: %w", err)
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
	return token, file, nil
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
