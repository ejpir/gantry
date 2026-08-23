package mcpworker

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const (
	muxVersion     = 1
	muxHeaderBytes = 16
	muxMaxPayload  = 64 << 10
	muxMaxStreams  = 64
	muxQueueDepth  = 4
	muxMaxOpenJSON = 1024
)

const (
	frameOpen byte = iota + 1
	frameOpenOK
	frameOpenError
	frameData
	frameClose
)

// OpenHandler validates and prepares an incoming stream. It must return without
// waiting for stream I/O; handler-owned goroutines may start immediately, and
// the mux gates their frames until the successful acknowledgement is on the wire.
type OpenHandler func(context.Context, OpenRequest, *Stream) error

// Mux carries bounded full-duplex byte streams over one inherited worker
// channel. Supervisor-opened stream IDs are even and worker-opened IDs are
// odd, preventing either side from colliding with an in-flight peer open.
type Mux struct {
	conn      net.Conn
	localEven bool
	onOpen    OpenHandler

	writeMu sync.Mutex
	mu      sync.Mutex
	nextID  uint64
	streams map[uint64]*Stream
	pending map[uint64]chan error
	sticky  error
	done    chan struct{}
	once    sync.Once
	opens   chan struct{}
}

func NewMux(conn net.Conn, localEven bool, onOpen OpenHandler) *Mux {
	next := uint64(1)
	if localEven {
		next = 2
	}
	mux := &Mux{
		conn: conn, localEven: localEven, onOpen: onOpen, nextID: next,
		streams: make(map[uint64]*Stream), pending: make(map[uint64]chan error),
		done: make(chan struct{}), opens: make(chan struct{}, 16),
	}
	go mux.readLoop()
	return mux
}

func (mux *Mux) Done() <-chan struct{} { return mux.done }

func (mux *Mux) Err() error {
	mux.mu.Lock()
	defer mux.mu.Unlock()
	return mux.sticky
}

func (mux *Mux) Open(ctx context.Context, request OpenRequest) (*Stream, error) {
	payload, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	if len(payload) == 0 || len(payload) > muxMaxOpenJSON {
		return nil, fmt.Errorf("mcp stream open payload is %d bytes", len(payload))
	}
	mux.mu.Lock()
	if mux.sticky != nil {
		err := mux.sticky
		mux.mu.Unlock()
		return nil, err
	}
	if len(mux.streams) >= muxMaxStreams {
		mux.mu.Unlock()
		return nil, fmt.Errorf("mcp stream limit reached")
	}
	id := mux.nextID
	mux.nextID += 2
	stream := newStream(mux, id)
	// Locally opened streams cannot escape to the caller before their
	// acknowledgement, so only peer-opened streams need an I/O readiness gate.
	stream.markReady()
	ack := make(chan error, 1)
	mux.streams[id] = stream
	mux.pending[id] = ack
	mux.mu.Unlock()

	if err := mux.writeFrame(frameOpen, id, payload); err != nil {
		mux.fail(err)
		return nil, err
	}
	select {
	case err := <-ack:
		if err != nil {
			stream.closeLocal(false)
			return nil, err
		}
		return stream, nil
	case <-ctx.Done():
		_ = stream.Close()
		return nil, ctx.Err()
	case <-mux.done:
		return nil, mux.Err()
	}
}

func (mux *Mux) Close() error {
	err := mux.conn.Close()
	mux.fail(net.ErrClosed)
	return err
}

func (mux *Mux) readLoop() {
	header := make([]byte, muxHeaderBytes)
	for {
		if _, err := io.ReadFull(mux.conn, header); err != nil {
			mux.fail(err)
			return
		}
		if header[0] != muxVersion || header[2] != 0 || header[3] != 0 {
			mux.fail(fmt.Errorf("mcp mux: malformed frame header"))
			return
		}
		typeID := header[1]
		id := binary.BigEndian.Uint64(header[4:12])
		size := binary.BigEndian.Uint32(header[12:16])
		if id == 0 || size > muxMaxPayload {
			mux.fail(fmt.Errorf("mcp mux: invalid stream %d payload size %d", id, size))
			return
		}
		payload := make([]byte, int(size))
		if _, err := io.ReadFull(mux.conn, payload); err != nil {
			mux.fail(err)
			return
		}
		if err := mux.receive(typeID, id, payload); err != nil {
			mux.fail(err)
			return
		}
	}
}

func (mux *Mux) receive(typeID byte, id uint64, payload []byte) error {
	switch typeID {
	case frameOpen:
		if (id%2 == 0) == mux.localEven {
			return fmt.Errorf("mcp mux: peer used local stream parity for %d", id)
		}
		if len(payload) == 0 || len(payload) > muxMaxOpenJSON {
			return fmt.Errorf("mcp mux: invalid open payload")
		}
		var request OpenRequest
		decoder := json.NewDecoder(bytes.NewReader(payload))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&request); err != nil {
			return fmt.Errorf("mcp mux: decode open: %w", err)
		}
		if err := ensureJSONEOF(decoder); err != nil {
			return fmt.Errorf("mcp mux: decode open: %w", err)
		}
		mux.mu.Lock()
		if mux.sticky != nil {
			mux.mu.Unlock()
			return mux.sticky
		}
		if len(mux.streams) >= muxMaxStreams {
			mux.mu.Unlock()
			return mux.writeFrame(frameOpenError, id, []byte("stream limit reached"))
		}
		if _, exists := mux.streams[id]; exists {
			mux.mu.Unlock()
			return fmt.Errorf("mcp mux: duplicate stream %d", id)
		}
		stream := newStream(mux, id)
		mux.streams[id] = stream
		mux.mu.Unlock()
		select {
		case mux.opens <- struct{}{}:
			go mux.handleOpen(request, stream)
		default:
			stream.closeLocal(false)
			return mux.writeFrame(frameOpenError, id, []byte("too many stream opens"))
		}
		return nil
	case frameOpenOK, frameOpenError:
		if len(payload) > 256 {
			return fmt.Errorf("mcp mux: oversized open acknowledgement")
		}
		mux.mu.Lock()
		ack := mux.pending[id]
		delete(mux.pending, id)
		mux.mu.Unlock()
		if ack == nil {
			return fmt.Errorf("mcp mux: acknowledgement for unknown stream %d", id)
		}
		if typeID == frameOpenError {
			message := string(payload)
			if message == "" {
				message = "stream refused"
			}
			ack <- errors.New(message)
		} else {
			if len(payload) != 0 {
				return fmt.Errorf("mcp mux: open acknowledgement has payload")
			}
			ack <- nil
		}
		return nil
	case frameData:
		if len(payload) == 0 {
			return fmt.Errorf("mcp mux: empty data frame")
		}
		stream := mux.stream(id)
		if stream == nil {
			return fmt.Errorf("mcp mux: data for unknown stream %d", id)
		}
		return stream.deliver(payload)
	case frameClose:
		if len(payload) != 0 {
			return fmt.Errorf("mcp mux: close frame has payload")
		}
		stream := mux.stream(id)
		if stream == nil {
			return nil // close acknowledgement raced final local cleanup
		}
		stream.closeRemote()
		return nil
	default:
		return fmt.Errorf("mcp mux: unknown frame type %d", typeID)
	}
}

func (mux *Mux) handleOpen(request OpenRequest, stream *Stream) {
	defer func() { <-mux.opens }()
	if mux.onOpen == nil {
		stream.closeLocal(false)
		err := mux.writeFrame(frameOpenError, stream.id, []byte("stream type unavailable"))
		stream.markReady()
		if err != nil {
			mux.fail(err)
		}
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	err := mux.onOpen(ctx, request, stream)
	cancel()
	if err != nil {
		stream.closeLocal(false)
		writeErr := mux.writeFrame(frameOpenError, stream.id, []byte("stream unavailable"))
		stream.markReady()
		if writeErr != nil {
			mux.fail(writeErr)
		}
		return
	}
	if err := mux.writeFrame(frameOpenOK, stream.id, nil); err != nil {
		mux.fail(err)
		return
	}
	// The peer must observe acceptance before a handler goroutine can emit a
	// data or close frame for the new stream.
	stream.markReady()
}

func (mux *Mux) stream(id uint64) *Stream {
	mux.mu.Lock()
	defer mux.mu.Unlock()
	return mux.streams[id]
}

func (mux *Mux) remove(id uint64, stream *Stream) {
	mux.mu.Lock()
	if mux.streams[id] == stream {
		delete(mux.streams, id)
		delete(mux.pending, id)
	}
	mux.mu.Unlock()
}

func (mux *Mux) writeFrame(typeID byte, id uint64, payload []byte) error {
	if len(payload) > muxMaxPayload {
		return fmt.Errorf("mcp mux: payload exceeds %d bytes", muxMaxPayload)
	}
	header := [muxHeaderBytes]byte{muxVersion, typeID}
	binary.BigEndian.PutUint64(header[4:12], id)
	binary.BigEndian.PutUint32(header[12:16], uint32(len(payload)))
	mux.writeMu.Lock()
	defer mux.writeMu.Unlock()
	if err := writeMuxBytes(mux.conn, header[:]); err != nil {
		return err
	}
	return writeMuxBytes(mux.conn, payload)
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("trailing JSON value")
		}
		return err
	}
	return nil
}

func writeMuxBytes(writer io.Writer, payload []byte) error {
	for len(payload) != 0 {
		written, err := writer.Write(payload)
		if err != nil {
			return err
		}
		if written <= 0 {
			return io.ErrShortWrite
		}
		payload = payload[written:]
	}
	return nil
}

func (mux *Mux) fail(err error) {
	if err == nil {
		err = net.ErrClosed
	}
	mux.once.Do(func() {
		mux.mu.Lock()
		mux.sticky = err
		streams := make([]*Stream, 0, len(mux.streams))
		for _, stream := range mux.streams {
			streams = append(streams, stream)
		}
		pending := mux.pending
		mux.streams = make(map[uint64]*Stream)
		mux.pending = make(map[uint64]chan error)
		mux.mu.Unlock()
		_ = mux.conn.Close()
		for _, ack := range pending {
			ack <- err
		}
		for _, stream := range streams {
			stream.abort()
		}
		close(mux.done)
	})
}

// Stream is a bounded net.Conn-like endpoint backed by Mux frames.
type Stream struct {
	mux *Mux
	id  uint64

	readMu  sync.Mutex
	writeMu sync.Mutex
	buf     []byte
	recv    chan []byte
	local   chan struct{}
	remote  chan struct{}
	abortC  chan struct{}
	ready   chan struct{}

	stateMu       sync.Mutex
	localClosed   bool
	remoteClosed  bool
	localOnce     sync.Once
	remoteOnce    sync.Once
	abortOnce     sync.Once
	readyOnce     sync.Once
	readDeadline  time.Time
	writeDeadline time.Time
	deadlineWake  chan struct{}
}

func newStream(mux *Mux, id uint64) *Stream {
	return &Stream{mux: mux, id: id, recv: make(chan []byte, muxQueueDepth),
		local: make(chan struct{}), remote: make(chan struct{}), abortC: make(chan struct{}),
		ready: make(chan struct{}), deadlineWake: make(chan struct{})}
}

func (stream *Stream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	stream.readMu.Lock()
	defer stream.readMu.Unlock()
	for len(stream.buf) == 0 {
		select {
		case data := <-stream.recv:
			stream.buf = data
			continue
		default:
		}
		stream.stateMu.Lock()
		deadline := stream.readDeadline
		wake := stream.deadlineWake
		stream.stateMu.Unlock()
		var timer <-chan time.Time
		if !deadline.IsZero() {
			if !time.Now().Before(deadline) {
				return 0, timeoutError("read")
			}
			t := time.NewTimer(time.Until(deadline))
			defer t.Stop()
			timer = t.C
		}
		select {
		case data := <-stream.recv:
			stream.buf = data
		case <-stream.remote:
			select {
			case data := <-stream.recv:
				stream.buf = data
			default:
				return 0, io.EOF
			}
		case <-stream.local:
			select {
			case <-stream.remote:
				select {
				case data := <-stream.recv:
					stream.buf = data
				default:
					return 0, io.EOF
				}
			default:
				return 0, net.ErrClosed
			}
		case <-stream.abortC:
			return 0, net.ErrClosed
		case <-wake:
			continue
		case <-timer:
			return 0, timeoutError("read")
		}
	}
	n := copy(p, stream.buf)
	stream.buf = stream.buf[n:]
	return n, nil
}

func (stream *Stream) Write(p []byte) (int, error) {
	stream.stateMu.Lock()
	closed := stream.localClosed
	deadline := stream.writeDeadline
	stream.stateMu.Unlock()
	if closed {
		return 0, net.ErrClosed
	}
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		return 0, timeoutError("write")
	}
	if len(p) == 0 {
		return 0, nil
	}
	if err := stream.waitReady(); err != nil {
		return 0, err
	}
	written := 0
	for len(p) != 0 {
		// Keep the closed-state check and frame write atomic with respect to
		// closeLocal. Otherwise a close frame can overtake a writer that already
		// observed the stream as open, leaving a data frame after the peer has
		// removed the stream.
		stream.writeMu.Lock()
		stream.stateMu.Lock()
		closed = stream.localClosed
		deadline = stream.writeDeadline
		stream.stateMu.Unlock()
		if closed {
			stream.writeMu.Unlock()
			return written, net.ErrClosed
		}
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			stream.writeMu.Unlock()
			return written, timeoutError("write")
		}
		n := min(len(p), muxMaxPayload)
		err := stream.mux.writeFrame(frameData, stream.id, p[:n])
		stream.writeMu.Unlock()
		if err != nil {
			stream.mux.fail(err)
			return written, err
		}
		written += n
		p = p[n:]
	}
	return written, nil
}

func (stream *Stream) Close() error {
	stream.closeLocal(true)
	return nil
}

func (stream *Stream) closeLocal(notify bool) {
	stream.writeMu.Lock()
	defer stream.writeMu.Unlock()

	stream.stateMu.Lock()
	if stream.localClosed {
		stream.stateMu.Unlock()
		return
	}
	stream.localClosed = true
	remoteClosed := stream.remoteClosed
	stream.stateMu.Unlock()
	stream.localOnce.Do(func() { close(stream.local) })
	if notify && stream.waitReadyForClose() {
		if err := stream.mux.writeFrame(frameClose, stream.id, nil); err != nil {
			stream.mux.fail(err)
		}
	}
	if remoteClosed || !notify {
		stream.mux.remove(stream.id, stream)
	}
}

func (stream *Stream) closeRemote() {
	stream.remoteOnce.Do(func() { close(stream.remote) })
	stream.stateMu.Lock()
	stream.remoteClosed = true
	localClosed := stream.localClosed
	stream.stateMu.Unlock()
	if !localClosed {
		stream.closeLocal(true) // acknowledge and release a peer-initiated close
	} else {
		stream.mux.remove(stream.id, stream)
	}
}

func (stream *Stream) abort() { stream.abortOnce.Do(func() { close(stream.abortC) }) }

func (stream *Stream) markReady() { stream.readyOnce.Do(func() { close(stream.ready) }) }

func (stream *Stream) waitReady() error {
	select {
	case <-stream.ready:
		return nil
	case <-stream.local:
		return net.ErrClosed
	case <-stream.abortC:
		return net.ErrClosed
	case <-stream.mux.done:
		return net.ErrClosed
	}
}

func (stream *Stream) waitReadyForClose() bool {
	select {
	case <-stream.ready:
		return true
	case <-stream.abortC:
		return false
	case <-stream.mux.done:
		return false
	}
}

func (stream *Stream) deliver(payload []byte) error {
	stream.stateMu.Lock()
	closed := stream.localClosed
	stream.stateMu.Unlock()
	if closed {
		return nil
	}
	data := append([]byte(nil), payload...)
	select {
	case stream.recv <- data:
		return nil
	case <-stream.local:
		return nil
	case <-stream.abortC:
		return net.ErrClosed
	case <-stream.mux.done:
		return net.ErrClosed
	}
}

func (stream *Stream) LocalAddr() net.Addr  { return muxAddr("local") }
func (stream *Stream) RemoteAddr() net.Addr { return muxAddr("remote") }
func (stream *Stream) SetDeadline(deadline time.Time) error {
	stream.stateMu.Lock()
	stream.readDeadline, stream.writeDeadline = deadline, deadline
	stream.signalDeadlineLocked()
	stream.stateMu.Unlock()
	return nil
}
func (stream *Stream) SetReadDeadline(deadline time.Time) error {
	stream.stateMu.Lock()
	stream.readDeadline = deadline
	stream.signalDeadlineLocked()
	stream.stateMu.Unlock()
	return nil
}
func (stream *Stream) SetWriteDeadline(deadline time.Time) error {
	stream.stateMu.Lock()
	stream.writeDeadline = deadline
	stream.signalDeadlineLocked()
	stream.stateMu.Unlock()
	return nil
}
func (stream *Stream) signalDeadlineLocked() {
	close(stream.deadlineWake)
	stream.deadlineWake = make(chan struct{})
}

type muxAddr string

func (addr muxAddr) Network() string { return "mcp-mux" }
func (addr muxAddr) String() string  { return string(addr) }

type deadlineError string

func (err deadlineError) Error() string { return string(err) + " timeout" }
func (deadlineError) Timeout() bool     { return true }
func (deadlineError) Temporary() bool   { return true }
func timeoutError(op string) error      { return deadlineError(op) }

var _ net.Conn = (*Stream)(nil)
