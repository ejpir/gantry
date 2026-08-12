package workerproto

import (
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"time"
)

const inheritedHandlePrefix = "GANTRY_WORKER_HANDLE_"
const inheritedAddressPrefix = "GANTRY_WORKER_ADDR_"
const inheritedReadPrefix = "GANTRY_WORKER_READ_"
const inheritedWritePrefix = "GANTRY_WORKER_WRITE_"

type windowsPipeConn struct {
	read      *os.File
	write     *os.File
	closeOnce sync.Once
	closeErr  error
}

type windowsPipeAddr struct{ name string }

func (a windowsPipeAddr) Network() string { return "windows-pipe" }
func (a windowsPipeAddr) String() string  { return a.name }

// NewPipeConn joins one read handle and one write handle into the full-duplex
// net.Conn surface used by workerproto. Windows anonymous pipe handles remain
// usable under restricted/AppContainer-style tokens because no new path or
// socket is opened in the worker.
func NewPipeConn(read, write *os.File) net.Conn {
	return &windowsPipeConn{read: read, write: write}
}

func (conn *windowsPipeConn) Read(data []byte) (int, error)  { return conn.read.Read(data) }
func (conn *windowsPipeConn) Write(data []byte) (int, error) { return conn.write.Write(data) }
func (conn *windowsPipeConn) Close() error {
	conn.closeOnce.Do(func() {
		conn.closeErr = conn.read.Close()
		if err := conn.write.Close(); conn.closeErr == nil {
			conn.closeErr = err
		}
	})
	return conn.closeErr
}
func (conn *windowsPipeConn) LocalAddr() net.Addr  { return windowsPipeAddr{"local"} }
func (conn *windowsPipeConn) RemoteAddr() net.Addr { return windowsPipeAddr{"remote"} }
func (conn *windowsPipeConn) SetDeadline(deadline time.Time) error {
	readErr := conn.read.SetReadDeadline(deadline)
	writeErr := conn.write.SetWriteDeadline(deadline)
	if readErr != nil && writeErr != nil {
		return fmt.Errorf("pipe deadlines: %w", readErr)
	}
	return nil
}
func (conn *windowsPipeConn) SetReadDeadline(deadline time.Time) error {
	return conn.read.SetReadDeadline(deadline)
}
func (conn *windowsPipeConn) SetWriteDeadline(deadline time.Time) error {
	return conn.write.SetWriteDeadline(deadline)
}

func inheritedPipeConn(slot uintptr, name string) (net.Conn, bool, error) {
	suffix := strconv.FormatUint(uint64(slot), 10)
	readRaw, writeRaw := os.Getenv(inheritedReadPrefix+suffix), os.Getenv(inheritedWritePrefix+suffix)
	if readRaw == "" && writeRaw == "" {
		return nil, false, nil
	}
	if readRaw == "" || writeRaw == "" {
		return nil, true, fmt.Errorf("inherited %s slot %d has incomplete pipe handles", name, slot)
	}
	readHandle, readErr := strconv.ParseUint(readRaw, 10, 64)
	writeHandle, writeErr := strconv.ParseUint(writeRaw, 10, 64)
	if readErr != nil || writeErr != nil || readHandle == 0 || writeHandle == 0 {
		return nil, true, fmt.Errorf("inherited %s slot %d has invalid pipe handles", name, slot)
	}
	read := os.NewFile(uintptr(readHandle), name+"-read")
	write := os.NewFile(uintptr(writeHandle), name+"-write")
	if read == nil || write == nil {
		if read != nil {
			_ = read.Close()
		}
		if write != nil {
			_ = write.Close()
		}
		return nil, true, fmt.Errorf("inherited %s slot %d pipe unavailable", name, slot)
	}
	return NewPipeConn(read, write), true, nil
}

// InheritedFile reconstructs one explicitly allowlisted Windows handle. The
// numeric value is not authority by itself: CreateProcess receives only the
// handles named in AdditionalInheritedHandles.
func InheritedFile(slot uintptr, name string) (*os.File, error) {
	raw := os.Getenv(inheritedHandlePrefix + strconv.FormatUint(uint64(slot), 10))
	if raw == "" {
		return nil, fmt.Errorf("inherited %s slot %d unavailable", name, slot)
	}
	handle, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || handle == 0 {
		return nil, fmt.Errorf("inherited %s slot %d has invalid handle %q", name, slot, raw)
	}
	file := os.NewFile(uintptr(handle), name)
	if file == nil {
		return nil, fmt.Errorf("inherited %s slot %d unavailable", name, slot)
	}
	return file, nil
}

// InheritedConn converts one inherited socket handle into a fresh pollable
// Go connection and closes the bootstrap handle.
func InheritedConn(slot uintptr, name string) (net.Conn, error) {
	if conn, present, err := inheritedPipeConn(slot, name); present {
		return conn, err
	}
	if address := os.Getenv(inheritedAddressPrefix + strconv.FormatUint(uint64(slot), 10)); address != "" {
		conn, err := net.Dial("tcp4", address)
		if err != nil {
			return nil, fmt.Errorf("connect inherited %s slot %d: %w", name, slot, err)
		}
		return conn, nil
	}
	file, err := InheritedFile(slot, name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	conn, err := net.FileConn(file)
	if err != nil {
		return nil, fmt.Errorf("inherited %s slot %d: %w", name, slot, err)
	}
	return conn, nil
}

var _ net.Conn = (*windowsPipeConn)(nil)
var _ io.ReadWriter = (*windowsPipeConn)(nil)
