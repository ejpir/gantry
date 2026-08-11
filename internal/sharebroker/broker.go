//go:build linux || darwin || windows

// Package sharebroker carries bounded raw FUSE requests between a virtio-fs
// frontend and a host-side request handler. It owns no host paths, filesystem
// policy, or virtio device state.
package sharebroker

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/ejpir/gantry/internal/fusewire"

	"github.com/hanwen/go-fuse/v2/fuse"
)

// The share broker protocol carries exactly one FUSE request/response at a
// time. The current virtio-mmio frontend is synchronous too, so serializing the
// stream preserves its ordering while placing a hard, connection-wide bound on
// allocations. It is deliberately binary: FUSE reads and writes are the hot
// path, and JSON would base64-expand every payload.
const (
	shareBrokerMagic        = uint32(0x47534631) // "GSF1"
	shareBrokerVersion      = uint16(2)
	shareBrokerRequest      = uint16(1)
	shareBrokerResponse     = uint16(2)
	shareBrokerNotification = uint16(3)
	shareBrokerNotifyReady  = uint16(4)
	shareBrokerHeaderSize   = 32
	shareBrokerMaxIOVs      = 65 // matches Core.availChain's maximum
	shareBrokerMaxErrno     = 4095
	shareBrokerHeaderMagic  = 0
	shareBrokerHeaderVer    = 4
	shareBrokerHeaderType   = 6
	shareBrokerHeaderID     = 8
	// MaxMessageBytes matches the virtio-fs descriptor-chain limit. Both
	// sides enforce it independently because either process may be hostile.
	MaxMessageBytes = 256 << 10
)

// Client forwards one ordered request at a time over a bounded byte stream.
// It contains no host path, directory descriptor, Windows handle, or virtio
// state.
type Client struct {
	rwc io.ReadWriteCloser

	callMu       sync.Mutex // one ordered request/response remains in flight
	writeMu      sync.Mutex // readiness control may race an ordinary request
	nextID       uint64
	header       [shareBrokerHeaderSize]byte
	lengths      [shareBrokerMaxIOVs]uint32
	wireLengths  [shareBrokerMaxIOVs * 4]byte
	writeVectors [shareBrokerMaxIOVs + 2][]byte
	writeBuffers net.Buffers

	responseReady    chan brokerClientResponse
	responseConsumed chan struct{}
	responseStorage  []byte
	stop             chan struct{}
	readDone         chan struct{}

	notifyMu      sync.Mutex
	notifySink    fusewire.NotificationSink
	pendingNotify [][]byte
	pendingBytes  int

	stateMu  sync.Mutex
	terminal error
	closeOne sync.Once
	stopOne  sync.Once
}

type brokerClientResponse struct {
	id     uint64
	status fuse.Status
	size   uint32
}

// NewClient takes ownership of rwc. The stream may be a Unix socketpair, a
// Windows named pipe, or any other reliable byte stream; the wire protocol has
// no OS-specific descriptor-passing requirement.
func NewClient(rwc io.ReadWriteCloser) (*Client, error) {
	if rwc == nil {
		return nil, fmt.Errorf("share broker client: nil transport")
	}
	client := &Client{
		rwc:              rwc,
		responseReady:    make(chan brokerClientResponse, 1),
		responseConsumed: make(chan struct{}, 1),
		stop:             make(chan struct{}),
		readDone:         make(chan struct{}),
		responseStorage:  make([]byte, MaxMessageBytes),
	}
	go client.readLoop()
	return client, nil
}

// Serve forwards requests to handler until the peer closes the stream or a
// malformed frame is received. It takes ownership of rwc but not handler. Callers
// must treat a protocol error as a fatal VMM-worker error; retrying a stateful
// FUSE request could repeat a host mutation.
func Serve(rwc io.ReadWriteCloser, handler fusewire.Handler) error {
	if handler == nil {
		return fmt.Errorf("share broker: nil handler")
	}
	if rwc == nil {
		return fmt.Errorf("share broker: nil transport")
	}
	writer := &brokerServerWriter{rwc: rwc}
	source, _ := handler.(fusewire.NotificationSource)
	defer func() {
		if source != nil {
			source.SetNotificationSink(nil)
		}
		_ = rwc.Close()
	}()

	var lastID uint64
	var frame brokerFrame
	for {
		if _, err := io.ReadFull(rwc, frame.header[:]); err != nil {
			if terminal := writer.err(); terminal != nil {
				return terminal
			}
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("share broker: read request header: %w", err)
		}
		messageType, err := parseShareBrokerMessageType(frame.header[:])
		if err != nil {
			return fmt.Errorf("share broker: %w", err)
		}
		if messageType == shareBrokerNotifyReady {
			ready, readyErr := parseShareBrokerNotifyReady(frame.header[:])
			if readyErr != nil {
				return fmt.Errorf("share broker: %w", readyErr)
			}
			if source == nil {
				return fmt.Errorf("share broker: peer enabled notifications for an incapable handler")
			}
			if ready {
				source.SetNotificationSink(writer.notification)
			} else {
				source.SetNotificationSink(nil)
			}
			continue
		}
		if messageType != shareBrokerRequest {
			return fmt.Errorf("share broker: unexpected client message type %d", messageType)
		}
		id, inLens, outLens, err := readShareBrokerRequest(rwc, frame.header[:], lastID, &frame.lengths, &frame.wireLengths)
		if err != nil {
			return fmt.Errorf("share broker: %w", err)
		}
		lastID = id

		in, err := frame.readInput(rwc, inLens)
		if err != nil {
			return fmt.Errorf("share broker: request %d input: %w", id, err)
		}
		if !fusewire.ValidRequest(in) {
			return fmt.Errorf("share broker: request %d has malformed FUSE input shape", id)
		}
		out := frame.prepareOutput(outLens)
		writer.beginRequest()
		n, status, callErr := callFuseHandler(handler, in, out)
		if callErr != nil {
			return fmt.Errorf("share broker: request %d: %w", id, callErr)
		}
		if len(outLens) == 0 {
			n = 0
		}
		if status != fuse.OK {
			n = 0
		} else if n < 0 || uint64(n) > sumBrokerLens(outLens) {
			return fmt.Errorf("share broker: request %d returned %d bytes for %d-byte output", id, n, sumBrokerLens(outLens))
		}
		if err := writer.response(id, status, frame.output[:n], &frame); err != nil {
			return fmt.Errorf("share broker: request %d response: %w", id, err)
		}
	}
}

type brokerServerWriter struct {
	rwc io.ReadWriteCloser
	mu  sync.Mutex

	stateMu sync.Mutex
	failure error

	activeRequest bool
	pending       [][]byte
	pendingBytes  int
}

func (w *brokerServerWriter) beginRequest() {
	w.mu.Lock()
	w.activeRequest = true
	w.mu.Unlock()
}

func (w *brokerServerWriter) response(id uint64, status fuse.Status, payload []byte, frame *brokerFrame) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.err(); err != nil {
		return err
	}
	if err := writeShareBrokerResponse(w.rwc, id, status, payload, &frame.header, &frame.responseVectors, &frame.responseBuffers); err != nil {
		w.fail(fmt.Errorf("write response: %w", err))
		return err
	}
	w.activeRequest = false
	for len(w.pending) != 0 {
		message := w.pending[0]
		w.pending[0] = nil
		w.pending = w.pending[1:]
		w.pendingBytes -= len(message)
		if err := w.writeNotificationLocked(message); err != nil {
			w.fail(err)
			return err
		}
	}
	w.pending = nil
	return nil
}

func (w *brokerServerWriter) notification(message []byte) fuse.Status {
	if !fusewire.ValidNotification(message) {
		return fuse.EINVAL
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.err() != nil {
		return fuse.EIO
	}
	if w.activeRequest {
		if len(w.pending) >= 70<<10 || w.pendingBytes+len(message) > 8<<20 {
			return fuse.EAGAIN
		}
		copyOfMessage := append([]byte(nil), message...)
		w.pending = append(w.pending, copyOfMessage)
		w.pendingBytes += len(copyOfMessage)
		return fuse.OK
	}
	if err := w.writeNotificationLocked(message); err != nil {
		w.fail(err)
		return fuse.EIO
	}
	return fuse.OK
}

func (w *brokerServerWriter) writeNotificationLocked(message []byte) error {
	var header [shareBrokerHeaderSize]byte
	var vectors [2][]byte
	var buffers net.Buffers
	putShareBrokerHeader(header[:], shareBrokerNotification, 0)
	binary.BigEndian.PutUint32(header[20:24], uint32(len(message)))
	binary.BigEndian.PutUint32(header[24:28], uint32(len(message)))
	vectors[0], vectors[1] = header[:], message
	buffers = vectors[:]
	if err := writeBrokerBuffers(w.rwc, &buffers); err != nil {
		return fmt.Errorf("share broker: write notification: %w", err)
	}
	return nil
}

func (w *brokerServerWriter) err() error {
	w.stateMu.Lock()
	defer w.stateMu.Unlock()
	return w.failure
}

func (w *brokerServerWriter) fail(err error) {
	w.stateMu.Lock()
	if w.failure == nil {
		w.failure = err
		_ = w.rwc.Close()
	}
	w.stateMu.Unlock()
}

// callFuseHandler turns a parser/backend panic into a fatal broker protocol
// error. The broker lives in the trusted supervisor, so malformed guest input
// must never unwind that process.
func callFuseHandler(handler fusewire.Handler, in, out [][]byte) (n int, status fuse.Status, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("FUSE handler panic: %v", recovered)
		}
	}()
	n, status = handler.HandleRequest(in, out)
	return n, status, nil
}

func (c *Client) HandleRequest(in, out [][]byte) (int, fuse.Status) {
	c.callMu.Lock()
	defer c.callMu.Unlock()

	if c.terminalError() != nil {
		return 0, fuse.EIO
	}
	inLens, outLens, err := validateBrokerIOV(in, out, &c.lengths)
	if err != nil {
		c.fail(err)
		return 0, fuse.EIO
	}
	if c.nextID == ^uint64(0) {
		c.fail(fmt.Errorf("share broker: request ID exhausted"))
		return 0, fuse.EIO
	}
	c.nextID++
	id := c.nextID
	c.writeMu.Lock()
	err = writeShareBrokerRequest(c.rwc, id, inLens, outLens, in, &c.header, &c.wireLengths, &c.writeVectors, &c.writeBuffers)
	c.writeMu.Unlock()
	if err != nil {
		c.fail(err)
		return 0, fuse.EIO
	}

	var response brokerClientResponse
	select {
	case response = <-c.responseReady:
	case <-c.readDone:
		return 0, fuse.EIO
	}
	consume := func() {
		select {
		case c.responseConsumed <- struct{}{}:
		case <-c.stop:
		}
	}
	if response.id != id || uint64(response.size) > sumBrokerLens(outLens) {
		consume()
		c.fail(fmt.Errorf("share broker: response %d/%d exceeds output cap %d", response.id, response.size, sumBrokerLens(outLens)))
		return 0, fuse.EIO
	}
	if response.status != fuse.OK {
		consume()
		return 0, response.status
	}
	copyBrokerOutput(out, c.responseStorage[:response.size])
	consume()
	return int(response.size), fuse.OK
}

// SetNotificationSink advertises readiness only after the virtio frontend has
// received a guest-provided notification buffer. The server does not attach
// the trusted filesystem source before this control frame arrives.
func (c *Client) SetNotificationSink(sink fusewire.NotificationSink) {
	if c == nil {
		return
	}
	c.notifyMu.Lock()
	c.notifySink = sink
	pending := c.pendingNotify
	c.pendingNotify = nil
	c.pendingBytes = 0
	c.notifyMu.Unlock()
	if sink != nil {
		for _, message := range pending {
			if status := sink(message); status != fuse.OK {
				c.fail(fmt.Errorf("share broker: queued notification rejected: %v", status))
				return
			}
		}
	}
	if c.terminalError() != nil {
		return
	}
	var header [shareBrokerHeaderSize]byte
	putShareBrokerHeader(header[:], shareBrokerNotifyReady, 0)
	if sink != nil {
		binary.BigEndian.PutUint32(header[16:20], 1)
	}
	c.writeMu.Lock()
	err := writeBrokerAll(c.rwc, header[:])
	c.writeMu.Unlock()
	if err != nil {
		c.fail(fmt.Errorf("share broker: write notification readiness: %w", err))
	}
}

func (c *Client) readLoop() {
	defer close(c.readDone)
	var header [shareBrokerHeaderSize]byte
	awaitingConsume := false
	for {
		if _, err := io.ReadFull(c.rwc, header[:]); err != nil {
			if c.terminalError() == nil {
				c.fail(fmt.Errorf("share broker: read server header: %w", err))
			}
			return
		}
		messageType, err := parseShareBrokerMessageType(header[:])
		if err != nil {
			c.fail(err)
			return
		}
		if awaitingConsume {
			select {
			case <-c.responseConsumed:
				awaitingConsume = false
			case <-c.stop:
				return
			}
		}
		switch messageType {
		case shareBrokerResponse:
			id, parseErr := parseShareBrokerHeader(header[:], shareBrokerResponse)
			if parseErr != nil {
				c.fail(parseErr)
				return
			}
			status, size, parseErr := parseShareBrokerResponse(header[:], id, MaxMessageBytes)
			if parseErr != nil {
				c.fail(parseErr)
				return
			}
			if _, readErr := io.ReadFull(c.rwc, c.responseStorage[:size]); readErr != nil {
				c.fail(fmt.Errorf("share broker: read response payload: %w", readErr))
				return
			}
			select {
			case c.responseReady <- brokerClientResponse{id: id, status: status, size: size}:
				awaitingConsume = true
			case <-c.stop:
				return
			}
		case shareBrokerNotification:
			size, parseErr := parseShareBrokerNotification(header[:])
			if parseErr != nil {
				c.fail(parseErr)
				return
			}
			message := make([]byte, size)
			if _, readErr := io.ReadFull(c.rwc, message); readErr != nil {
				c.fail(fmt.Errorf("share broker: read notification: %w", readErr))
				return
			}
			if !fusewire.ValidNotification(message) {
				c.fail(fmt.Errorf("share broker: malformed FUSE notification"))
				return
			}
			if !c.deliverNotification(message) {
				return
			}
		default:
			c.fail(fmt.Errorf("share broker: unexpected server message type %d", messageType))
			return
		}
	}
}

func (c *Client) deliverNotification(message []byte) bool {
	c.notifyMu.Lock()
	sink := c.notifySink
	if sink == nil {
		if len(c.pendingNotify) >= 1024 || c.pendingBytes+len(message) > 1<<20 {
			c.notifyMu.Unlock()
			c.fail(fmt.Errorf("share broker: notification arrived without guest buffers"))
			return false
		}
		c.pendingNotify = append(c.pendingNotify, message)
		c.pendingBytes += len(message)
		c.notifyMu.Unlock()
		return true
	}
	c.notifyMu.Unlock()
	if status := sink(message); status != fuse.OK {
		c.fail(fmt.Errorf("share broker: notification transport failed: %v", status))
		return false
	}
	return true
}

func (c *Client) terminalError() error {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	return c.terminal
}

func (c *Client) fail(err error) {
	c.stateMu.Lock()
	if c.terminal == nil {
		c.terminal = err
	}
	c.stateMu.Unlock()
	c.stopOne.Do(func() { close(c.stop) })
	c.closeOne.Do(func() { _ = c.rwc.Close() })
}

func (c *Client) Close() error {
	c.stateMu.Lock()
	if c.terminal == nil {
		c.terminal = io.ErrClosedPipe
	}
	c.stateMu.Unlock()
	c.stopOne.Do(func() { close(c.stop) })
	var err error
	c.closeOne.Do(func() { err = c.rwc.Close() })
	<-c.readDone
	return err
}

func copyBrokerOutput(out [][]byte, payload []byte) {
	offset := 0
	for _, part := range out {
		if offset == len(payload) {
			return
		}
		offset += copy(part, payload[offset:])
	}
}

func validateBrokerIOV(in, out [][]byte, lengths *[shareBrokerMaxIOVs]uint32) ([]uint32, []uint32, error) {
	if !fusewire.ValidRequest(in) {
		return nil, nil, fmt.Errorf("share broker: malformed FUSE input shape")
	}
	if len(in)+len(out) > shareBrokerMaxIOVs {
		return nil, nil, fmt.Errorf("share broker: %d IOVs exceed cap %d", len(in)+len(out), shareBrokerMaxIOVs)
	}
	inLens := lengths[:len(in)]
	outLens := lengths[len(in) : len(in)+len(out)]
	var total uint64
	for i, b := range in {
		inLens[i] = uint32(len(b))
		total += uint64(len(b))
	}
	for i, b := range out {
		outLens[i] = uint32(len(b))
		total += uint64(len(b))
	}
	if total > MaxMessageBytes {
		return nil, nil, fmt.Errorf("share broker: IOV bytes %d exceed cap %d", total, MaxMessageBytes)
	}
	return inLens, outLens, nil
}

func writeShareBrokerRequest(w io.Writer, id uint64, inLens, outLens []uint32, in [][]byte, header *[shareBrokerHeaderSize]byte, table *[shareBrokerMaxIOVs * 4]byte, vectors *[shareBrokerMaxIOVs + 2][]byte, buffers *net.Buffers) error {
	clear(header[:])
	putShareBrokerHeader(header[:], shareBrokerRequest, id)
	binary.BigEndian.PutUint16(header[16:18], uint16(len(inLens)))
	binary.BigEndian.PutUint16(header[18:20], uint16(len(outLens)))
	binary.BigEndian.PutUint32(header[20:24], uint32(sumBrokerLens(inLens)))
	binary.BigEndian.PutUint32(header[24:28], uint32(sumBrokerLens(outLens)))
	lengths := table[:4*(len(inLens)+len(outLens))]
	for i, n := range inLens {
		binary.BigEndian.PutUint32(lengths[i*4:], n)
	}
	offset := 4 * len(inLens)
	for i, n := range outLens {
		binary.BigEndian.PutUint32(lengths[offset+i*4:], n)
	}
	// Submit the complete frame with one writev on Unix sockets. Separate
	// header/table/payload writes can wake the broker between fragments,
	// multiplying context switches for metadata-heavy workloads.
	clear(vectors[:])
	vectors[0] = header[:]
	vectors[1] = lengths
	count := 2
	for _, part := range in {
		if len(part) == 0 {
			continue
		}
		vectors[count] = part
		count++
	}
	*buffers = vectors[:count]
	if err := writeBrokerBuffers(w, buffers); err != nil {
		return fmt.Errorf("share broker: write request: %w", err)
	}
	return nil
}

func readShareBrokerRequest(r io.Reader, hdr []byte, lastID uint64, lengths *[shareBrokerMaxIOVs]uint32, table *[shareBrokerMaxIOVs * 4]byte) (uint64, []uint32, []uint32, error) {
	id, err := parseShareBrokerHeader(hdr, shareBrokerRequest)
	if err != nil {
		return 0, nil, nil, err
	}
	if id == 0 || id != lastID+1 {
		return 0, nil, nil, fmt.Errorf("request ID %d is not next after %d", id, lastID)
	}
	inCount := int(binary.BigEndian.Uint16(hdr[16:18]))
	outCount := int(binary.BigEndian.Uint16(hdr[18:20]))
	if inCount == 0 || inCount+outCount > shareBrokerMaxIOVs {
		return 0, nil, nil, fmt.Errorf("invalid IOV counts %d+%d", inCount, outCount)
	}
	wantIn := uint64(binary.BigEndian.Uint32(hdr[20:24]))
	wantOut := uint64(binary.BigEndian.Uint32(hdr[24:28]))
	if binary.BigEndian.Uint32(hdr[28:32]) != 0 {
		return 0, nil, nil, fmt.Errorf("request reserved field is nonzero")
	}
	if wantIn+wantOut > MaxMessageBytes {
		return 0, nil, nil, fmt.Errorf("request bytes %d exceed cap %d", wantIn+wantOut, MaxMessageBytes)
	}

	wireLengths := table[:4*(inCount+outCount)]
	if _, err := io.ReadFull(r, wireLengths); err != nil {
		return 0, nil, nil, fmt.Errorf("read IOV lengths: %w", err)
	}
	inLens := lengths[:inCount]
	outLens := lengths[inCount : inCount+outCount]
	for i := range inLens {
		inLens[i] = binary.BigEndian.Uint32(wireLengths[i*4:])
	}
	for i := range outLens {
		outLens[i] = binary.BigEndian.Uint32(wireLengths[(inCount+i)*4:])
	}
	if sumBrokerLens(inLens) != wantIn || sumBrokerLens(outLens) != wantOut {
		return 0, nil, nil, fmt.Errorf("IOV lengths do not match declared totals")
	}
	return id, inLens, outLens, nil
}

type brokerFrame struct {
	header          [shareBrokerHeaderSize]byte
	lengths         [shareBrokerMaxIOVs]uint32
	wireLengths     [shareBrokerMaxIOVs * 4]byte
	input           []byte
	output          []byte
	inIOV           [shareBrokerMaxIOVs][]byte
	outIOV          [shareBrokerMaxIOVs][]byte
	responseVectors [2][]byte
	responseBuffers net.Buffers
}

func (f *brokerFrame) readInput(r io.Reader, lengths []uint32) ([][]byte, error) {
	f.input = resizeBrokerBuffer(f.input, int(sumBrokerLens(lengths)))
	if _, err := io.ReadFull(r, f.input); err != nil {
		return nil, err
	}
	clear(f.inIOV[:])
	return sliceBrokerIOV(f.inIOV[:len(lengths)], f.input, lengths), nil
}

func (f *brokerFrame) prepareOutput(lengths []uint32) [][]byte {
	f.output = resizeBrokerBuffer(f.output, int(sumBrokerLens(lengths)))
	clear(f.output)
	clear(f.outIOV[:])
	return sliceBrokerIOV(f.outIOV[:len(lengths)], f.output, lengths)
}

func resizeBrokerBuffer(buf []byte, size int) []byte {
	if cap(buf) < size {
		return make([]byte, size)
	}
	return buf[:size]
}

func sliceBrokerIOV(dst [][]byte, buf []byte, lengths []uint32) [][]byte {
	offset := 0
	for i, length := range lengths {
		next := offset + int(length)
		dst[i] = buf[offset:next]
		offset = next
	}
	return dst
}

func writeShareBrokerResponse(w io.Writer, id uint64, status fuse.Status, payload []byte, header *[shareBrokerHeaderSize]byte, vectors *[2][]byte, buffers *net.Buffers) error {
	clear(header[:])
	putShareBrokerHeader(header[:], shareBrokerResponse, id)
	binary.BigEndian.PutUint32(header[16:20], uint32(int32(status)))
	binary.BigEndian.PutUint32(header[20:24], uint32(len(payload)))
	binary.BigEndian.PutUint32(header[24:28], uint32(len(payload)))
	// Keep header and payload in one socket write for the same reason as
	// request framing: one completed response should produce one peer wakeup.
	vectors[0] = header[:]
	count := 1
	if len(payload) != 0 {
		vectors[1] = payload
		count++
	}
	*buffers = vectors[:count]
	return writeBrokerBuffers(w, buffers)
}

func parseShareBrokerResponse(hdr []byte, wantID uint64, outCap uint64) (fuse.Status, uint32, error) {
	id, err := parseShareBrokerHeader(hdr, shareBrokerResponse)
	if err != nil {
		return fuse.EIO, 0, err
	}
	if id != wantID {
		return fuse.EIO, 0, fmt.Errorf("share broker: response ID %d, want %d", id, wantID)
	}
	status := fuse.Status(int32(binary.BigEndian.Uint32(hdr[16:20])))
	n := binary.BigEndian.Uint32(hdr[20:24])
	payloadLen := binary.BigEndian.Uint32(hdr[24:28])
	if binary.BigEndian.Uint32(hdr[28:32]) != 0 {
		return fuse.EIO, 0, fmt.Errorf("share broker: response reserved field is nonzero")
	}
	if status < 0 || status > shareBrokerMaxErrno {
		return fuse.EIO, 0, fmt.Errorf("share broker: invalid FUSE status %d", status)
	}
	if status != fuse.OK {
		if n != 0 || payloadLen != 0 {
			return fuse.EIO, 0, fmt.Errorf("share broker: error response carries payload")
		}
		return status, 0, nil
	}
	if n != payloadLen || uint64(n) > outCap || uint64(n) > MaxMessageBytes {
		return fuse.EIO, 0, fmt.Errorf("share broker: response length %d/%d outside output cap %d", n, payloadLen, outCap)
	}
	return fuse.OK, n, nil
}

func putShareBrokerHeader(hdr []byte, typ uint16, id uint64) {
	binary.BigEndian.PutUint32(hdr[shareBrokerHeaderMagic:shareBrokerHeaderVer], shareBrokerMagic)
	binary.BigEndian.PutUint16(hdr[shareBrokerHeaderVer:shareBrokerHeaderType], shareBrokerVersion)
	binary.BigEndian.PutUint16(hdr[shareBrokerHeaderType:shareBrokerHeaderID], typ)
	binary.BigEndian.PutUint64(hdr[shareBrokerHeaderID:16], id)
}

func parseShareBrokerMessageType(hdr []byte) (uint16, error) {
	if len(hdr) != shareBrokerHeaderSize {
		return 0, fmt.Errorf("short protocol header")
	}
	if binary.BigEndian.Uint32(hdr[shareBrokerHeaderMagic:shareBrokerHeaderVer]) != shareBrokerMagic {
		return 0, fmt.Errorf("bad protocol magic")
	}
	if binary.BigEndian.Uint16(hdr[shareBrokerHeaderVer:shareBrokerHeaderType]) != shareBrokerVersion {
		return 0, fmt.Errorf("unsupported protocol version")
	}
	return binary.BigEndian.Uint16(hdr[shareBrokerHeaderType:shareBrokerHeaderID]), nil
}

func parseShareBrokerNotifyReady(hdr []byte) (bool, error) {
	id, err := parseShareBrokerHeader(hdr, shareBrokerNotifyReady)
	if err != nil {
		return false, err
	}
	ready := binary.BigEndian.Uint32(hdr[16:20])
	if id != 0 || ready > 1 || binary.BigEndian.Uint64(hdr[20:28]) != 0 || binary.BigEndian.Uint32(hdr[28:32]) != 0 {
		return false, fmt.Errorf("malformed notification readiness frame")
	}
	return ready == 1, nil
}

func parseShareBrokerNotification(hdr []byte) (int, error) {
	id, err := parseShareBrokerHeader(hdr, shareBrokerNotification)
	if err != nil {
		return 0, err
	}
	size := binary.BigEndian.Uint32(hdr[20:24])
	if id != 0 || binary.BigEndian.Uint32(hdr[16:20]) != 0 || size == 0 ||
		size != binary.BigEndian.Uint32(hdr[24:28]) || size > fusewire.MaxNotificationBytes ||
		binary.BigEndian.Uint32(hdr[28:32]) != 0 {
		return 0, fmt.Errorf("malformed notification frame")
	}
	return int(size), nil
}

func parseShareBrokerHeader(hdr []byte, wantType uint16) (uint64, error) {
	if len(hdr) != shareBrokerHeaderSize {
		return 0, fmt.Errorf("short protocol header")
	}
	if binary.BigEndian.Uint32(hdr[shareBrokerHeaderMagic:shareBrokerHeaderVer]) != shareBrokerMagic {
		return 0, fmt.Errorf("bad protocol magic")
	}
	if binary.BigEndian.Uint16(hdr[shareBrokerHeaderVer:shareBrokerHeaderType]) != shareBrokerVersion {
		return 0, fmt.Errorf("unsupported protocol version")
	}
	if got := binary.BigEndian.Uint16(hdr[shareBrokerHeaderType:shareBrokerHeaderID]); got != wantType {
		return 0, fmt.Errorf("message type %d, want %d", got, wantType)
	}
	return binary.BigEndian.Uint64(hdr[shareBrokerHeaderID:16]), nil
}

func sumBrokerLens(lens []uint32) uint64 {
	var total uint64
	for _, n := range lens {
		total += uint64(n)
	}
	return total
}

func writeBrokerAll(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}

var (
	_ fusewire.Handler            = (*Client)(nil)
	_ fusewire.NotificationSource = (*Client)(nil)
)

func writeBrokerBuffers(w io.Writer, buffers *net.Buffers) error {
	var want int64
	for _, buffer := range *buffers {
		want += int64(len(buffer))
	}
	written, err := buffers.WriteTo(w)
	if err != nil {
		return err
	}
	if written != want {
		return io.ErrShortWrite
	}
	return nil
}
