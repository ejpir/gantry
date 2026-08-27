// Package diskbroker mediates fixed-size writable virtio-blk images for a
// split VMM. The trusted supervisor retains and locks each host file; the
// confined VMM worker receives only this bounded request stream.
package diskbroker

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

const (
	protocolMagic   = uint32(0x47444231) // "GDB1"
	protocolVersion = uint16(1)
	headerSize      = 32
	maxPayloadBytes = 4 << 20
	requestTimeout  = 30 * time.Second

	opRead  = uint16(1)
	opWrite = uint16(2)
	opSync  = uint16(3)

	statusOK      = uint32(0)
	statusIO      = uint32(1)
	statusInvalid = uint32(2)
)

// Client is a synchronous fixed-size block backend. One virtio-blk queue
// issues one request at a time, and the mutex also fails closed if a future
// caller attempts concurrent use.
type Client struct {
	conn net.Conn
	name string
	size uint64

	mu       sync.Mutex
	nextID   uint64
	terminal error
	closeOne sync.Once
	closeErr error
}

// NewClient takes ownership of conn after validating the authenticated size
// supplied by the supervisor bootstrap payload.
func NewClient(conn net.Conn, name string, size uint64) (*Client, error) {
	if conn == nil {
		return nil, errors.New("disk broker client: nil transport")
	}
	if size == 0 || size > uint64(^uint64(0)>>1) {
		return nil, fmt.Errorf("disk broker client: invalid size %d", size)
	}
	if name == "" {
		name = "brokered-disk"
	}
	return &Client{conn: conn, name: name, size: size}, nil
}

func (client *Client) Name() string { return client.name }
func (client *Client) Size() uint64 { return client.size }

func (client *Client) ReadAt(buffer []byte, offset int64) (int, error) {
	if len(buffer) == 0 {
		return 0, nil
	}
	if err := client.bounds(offset, len(buffer)); err != nil {
		return 0, err
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if err := client.setRequestDeadlineLocked(); err != nil {
		return 0, err
	}
	defer client.clearDeadlineLocked()
	id, err := client.beginLocked(opRead, offset, len(buffer), nil)
	if err != nil {
		return 0, err
	}
	if err := client.responseLocked(opRead, id, offset, len(buffer)); err != nil {
		return 0, err
	}
	if _, err := io.ReadFull(client.conn, buffer); err != nil {
		return 0, client.failLocked(fmt.Errorf("disk broker read payload: %w", err))
	}
	return len(buffer), nil
}

func (client *Client) WriteAt(buffer []byte, offset int64) (int, error) {
	if len(buffer) == 0 {
		return 0, nil
	}
	if err := client.bounds(offset, len(buffer)); err != nil {
		return 0, err
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if err := client.setRequestDeadlineLocked(); err != nil {
		return 0, err
	}
	defer client.clearDeadlineLocked()
	id, err := client.beginLocked(opWrite, offset, len(buffer), buffer)
	if err != nil {
		return 0, err
	}
	if err := client.responseLocked(opWrite, id, offset, len(buffer)); err != nil {
		return 0, err
	}
	return len(buffer), nil
}

func (client *Client) Sync() error {
	client.mu.Lock()
	defer client.mu.Unlock()
	if err := client.setRequestDeadlineLocked(); err != nil {
		return err
	}
	defer client.clearDeadlineLocked()
	id, err := client.beginLocked(opSync, 0, 0, nil)
	if err != nil {
		return err
	}
	return client.responseLocked(opSync, id, 0, 0)
}

func (client *Client) setRequestDeadlineLocked() error {
	if client.terminal != nil {
		return client.terminal
	}
	if err := client.conn.SetDeadline(time.Now().Add(requestTimeout)); err != nil {
		return client.failLocked(fmt.Errorf("disk broker set request deadline: %w", err))
	}
	return nil
}

func (client *Client) clearDeadlineLocked() {
	_ = client.conn.SetDeadline(time.Time{})
}

func (client *Client) bounds(offset int64, length int) error {
	if offset < 0 || length < 0 || length > maxPayloadBytes || uint64(offset) > client.size || uint64(length) > client.size-uint64(offset) {
		return fmt.Errorf("disk broker %s: request offset %d length %d exceeds %d-byte device", client.name, offset, length, client.size)
	}
	return nil
}

func (client *Client) beginLocked(operation uint16, offset int64, length int, payload []byte) (uint64, error) {
	if client.terminal != nil {
		return 0, client.terminal
	}
	if client.nextID == ^uint64(0) {
		return 0, client.failLocked(errors.New("disk broker request ID exhausted"))
	}
	client.nextID++
	id := client.nextID
	var header [headerSize]byte
	putHeader(header[:], operation, id, uint64(offset), uint32(length), statusOK)
	if err := writeAll(client.conn, header[:]); err != nil {
		return 0, client.failLocked(fmt.Errorf("disk broker write request: %w", err))
	}
	if len(payload) != 0 {
		if err := writeAll(client.conn, payload); err != nil {
			return 0, client.failLocked(fmt.Errorf("disk broker write payload: %w", err))
		}
	}
	return id, nil
}

func (client *Client) responseLocked(operation uint16, id uint64, offset int64, length int) error {
	var header [headerSize]byte
	if _, err := io.ReadFull(client.conn, header[:]); err != nil {
		return client.failLocked(fmt.Errorf("disk broker read response: %w", err))
	}
	gotOperation, gotID, gotOffset, gotLength, status, err := parseHeader(header[:])
	if err != nil {
		return client.failLocked(err)
	}
	if gotOperation != operation || gotID != id || gotOffset != uint64(offset) || gotLength != uint32(length) {
		return client.failLocked(fmt.Errorf("disk broker mismatched response op=%d id=%d offset=%d length=%d", gotOperation, gotID, gotOffset, gotLength))
	}
	switch status {
	case statusOK:
		return nil
	case statusIO:
		return fmt.Errorf("disk broker %s: host I/O failed", client.name)
	case statusInvalid:
		return client.failLocked(fmt.Errorf("disk broker %s: supervisor rejected request bounds", client.name))
	default:
		return client.failLocked(fmt.Errorf("disk broker %s: invalid response status %d", client.name, status))
	}
}

func (client *Client) failLocked(err error) error {
	if client.terminal == nil {
		client.terminal = err
		client.closeOne.Do(func() { client.closeErr = client.conn.Close() })
	}
	return client.terminal
}

func (client *Client) Close() error {
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.terminal == nil {
		client.terminal = net.ErrClosed
	}
	client.closeOne.Do(func() { client.closeErr = client.conn.Close() })
	return client.closeErr
}

// Serve handles requests until the worker closes transport. It borrows disk;
// the supervisor-owned relay closes and syncs the file after Serve returns.
func Serve(conn net.Conn, disk *os.File, size uint64) error {
	if conn == nil || disk == nil {
		return errors.New("disk broker: nil transport or disk")
	}
	if size == 0 || size > uint64(^uint64(0)>>1) {
		return fmt.Errorf("disk broker: invalid device size %d", size)
	}
	buffer := make([]byte, maxPayloadBytes)
	var lastID uint64
	var header [headerSize]byte
	for {
		if _, err := io.ReadFull(conn, header[:]); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("disk broker read request: %w", err)
		}
		operation, id, offset, length, status, err := parseHeader(header[:])
		if err != nil {
			return err
		}
		if status != statusOK || id == 0 || id <= lastID {
			return fmt.Errorf("disk broker invalid request sequence id=%d status=%d", id, status)
		}
		lastID = id
		if err := conn.SetDeadline(time.Now().Add(requestTimeout)); err != nil {
			return fmt.Errorf("disk broker set active request deadline: %w", err)
		}
		validBounds := length <= maxPayloadBytes && offset <= size && uint64(length) <= size-offset
		responseStatus := statusOK
		switch operation {
		case opRead:
			if !validBounds {
				responseStatus = statusInvalid
			} else if _, err := disk.ReadAt(buffer[:length], int64(offset)); err != nil {
				responseStatus = statusIO
			}
			putHeader(header[:], operation, id, offset, length, responseStatus)
			if err := writeAll(conn, header[:]); err != nil {
				return fmt.Errorf("disk broker write read response: %w", err)
			}
			if responseStatus == statusOK {
				if err := writeAll(conn, buffer[:length]); err != nil {
					return fmt.Errorf("disk broker write read payload: %w", err)
				}
			}
		case opWrite:
			if length > maxPayloadBytes {
				return fmt.Errorf("disk broker oversized write payload %d", length)
			}
			if _, err := io.ReadFull(conn, buffer[:length]); err != nil {
				return fmt.Errorf("disk broker read write payload: %w", err)
			}
			if !validBounds {
				responseStatus = statusInvalid
			} else if _, err := disk.WriteAt(buffer[:length], int64(offset)); err != nil {
				responseStatus = statusIO
			}
			putHeader(header[:], operation, id, offset, length, responseStatus)
			if err := writeAll(conn, header[:]); err != nil {
				return fmt.Errorf("disk broker write response: %w", err)
			}
		case opSync:
			if offset != 0 || length != 0 {
				responseStatus = statusInvalid
			} else if err := disk.Sync(); err != nil {
				responseStatus = statusIO
			}
			putHeader(header[:], operation, id, offset, length, responseStatus)
			if err := writeAll(conn, header[:]); err != nil {
				return fmt.Errorf("disk broker write sync response: %w", err)
			}
		default:
			return fmt.Errorf("disk broker unsupported operation %d", operation)
		}
		_ = conn.SetDeadline(time.Time{})
	}
}

func putHeader(header []byte, operation uint16, id, offset uint64, length, status uint32) {
	clear(header)
	binary.BigEndian.PutUint32(header[0:4], protocolMagic)
	binary.BigEndian.PutUint16(header[4:6], protocolVersion)
	binary.BigEndian.PutUint16(header[6:8], operation)
	binary.BigEndian.PutUint64(header[8:16], id)
	binary.BigEndian.PutUint64(header[16:24], offset)
	binary.BigEndian.PutUint32(header[24:28], length)
	binary.BigEndian.PutUint32(header[28:32], status)
}

func parseHeader(header []byte) (operation uint16, id, offset uint64, length, status uint32, err error) {
	if len(header) != headerSize || binary.BigEndian.Uint32(header[0:4]) != protocolMagic || binary.BigEndian.Uint16(header[4:6]) != protocolVersion {
		return 0, 0, 0, 0, 0, errors.New("disk broker malformed header")
	}
	return binary.BigEndian.Uint16(header[6:8]), binary.BigEndian.Uint64(header[8:16]),
		binary.BigEndian.Uint64(header[16:24]), binary.BigEndian.Uint32(header[24:28]), binary.BigEndian.Uint32(header[28:32]), nil
}

func writeAll(writer io.Writer, buffer []byte) error {
	for len(buffer) != 0 {
		count, err := writer.Write(buffer)
		if count > 0 {
			buffer = buffer[count:]
		}
		if err != nil {
			return err
		}
		if count == 0 {
			return io.ErrNoProgress
		}
	}
	return nil
}
