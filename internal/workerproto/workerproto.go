// Package workerproto is the versioned, bounded wire protocol between a
// gantry supervisor and its re-executed worker processes (see
// docs/vmm-network-isolation.md). It provides:
//
//   - a control channel: one handshake, then synchronous request/response
//     messages, each a 4-byte big-endian length prefix plus a JSON body,
//     hard-capped at MaxMessage;
//   - a data channel: QEMU-framed Ethernet frames (4-byte big-endian
//     length + raw frame), hard-capped at MaxFrame, carrying NO control
//     information of any kind;
//   - a launch nonce that crosses both channels so a worker can verify
//     its two inherited descriptors belong to the same supervisor launch
//     (cross-wiring check).
//
// The protocol is private to the one gantry executable — supervisor and
// worker are always the same binary — but it is versioned and strict
// anyway: unknown magic/role/operations, duplicate request IDs, oversized
// messages, and oversized frames are all fatal protocol errors, so a
// confused or compromised peer fails closed instead of being interpreted.
// This is NOT a public compatibility API.
package workerproto

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const (
	// Magic identifies protocol version 1 of the control handshake.
	Magic = "GANTRY-WORKER/1"
	// RoleVMM owns the hypervisor, guest RAM, virtio device frontends,
	// disk I/O, and the vsock data plane. Host share serving remains in
	// the trusted supervisor behind a bounded request relay (Phase 2).
	RoleVMM = "vmm"
	// RoleNet owns the netstack, egress policy, traffic accounting, and
	// port listeners (Phase 1 of the
	// network-isolation design); a VMM worker role arrives with Phase 2.
	RoleNet = "net"

	// MaxMessage caps one control message (length prefix excluded). A
	// policy with thousands of allowlisted domains is still far under
	// this; anything larger is a protocol violation, not a big policy.
	MaxMessage = 1 << 20
	// MaxFrame caps one Ethernet frame on the data channel. Must match
	// virtioNetMaxFrame in internal/virtio (65562): the largest frame
	// the device model will ever emit or accept.
	MaxFrame = 65562
	// MaxConcurrentHandlers bounds handler goroutines retained by one
	// control connection. One slot may remain parked for vm.wait; the
	// rest absorb normal control bursts without allowing a compromised
	// peer to grow supervisor goroutines and resources without bound.
	MaxConcurrentHandlers = 32

	// nonceLen is the raw byte length of the launch nonce.
	nonceLen = 32

	// handshakeOps are bounded tighter than steady-state calls: a wedged
	// spawn must fail fast enough to surface as a boot error.
	handshakeTimeout = 15 * time.Second
)

// Handshake is the first and only supervisor→worker control message that
// is not a Request. Config carries the role-specific bootstrap payload
// (already parsed and normalized by the supervisor — a worker NEVER
// receives a host path to interpret on its own authority).
type Handshake struct {
	Magic  string          `json:"magic"`
	Role   string          `json:"role"`
	Nonce  string          `json:"nonce"` // hex(nonceLen random bytes)
	Config json.RawMessage `json:"config"`
}

// NewNonce generates a fresh launch nonce (raw bytes).
func NewNonce() []byte {
	b := make([]byte, nonceLen)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand failure is unrecoverable by design
	}
	return b
}

// WriteMessage frames one JSON control message.
func WriteMessage(w io.Writer, v any) error {
	body, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(body) > MaxMessage {
		return fmt.Errorf("workerproto: message %d bytes > cap %d", len(body), MaxMessage)
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(body)))
	if _, err := w.Write(append(hdr[:], body...)); err != nil {
		return fmt.Errorf("workerproto: write: %w", err)
	}
	return nil
}

// ReadMessage reads one framed JSON control message. A length outside
// 1..MaxMessage is a fatal protocol error (the allocation is bounded by
// the validated length, never by the declared one).
func ReadMessage(r io.Reader, v any) error {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return fmt.Errorf("workerproto: read header: %w", err)
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > MaxMessage {
		return fmt.Errorf("workerproto: message length %d out of bounds", n)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return fmt.Errorf("workerproto: read body: %w", err)
	}
	if err := json.Unmarshal(body, v); err != nil {
		return fmt.Errorf("workerproto: decode: %w", err)
	}
	return nil
}

// WriteFrame writes one QEMU-framed Ethernet frame on the data channel.
func WriteFrame(w io.Writer, frame []byte) error {
	if len(frame) == 0 || len(frame) > MaxFrame {
		return fmt.Errorf("workerproto: frame length %d out of bounds", len(frame))
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(frame)))
	if _, err := w.Write(append(hdr[:], frame...)); err != nil {
		return fmt.Errorf("workerproto: write frame: %w", err)
	}
	return nil
}

// ReadFrame reads one QEMU-framed Ethernet frame into buf, which must be
// at least MaxFrame bytes. A declared length outside 1..MaxFrame — or
// larger than buf — is a fatal protocol error: the peer is malformed or
// hostile and the caller must tear the link down.
func ReadFrame(r io.Reader, buf []byte) (int, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > MaxFrame || int(n) > len(buf) {
		return 0, fmt.Errorf("workerproto: frame length %d out of bounds", n)
	}
	m, err := io.ReadFull(r, buf[:n])
	if err != nil {
		return 0, err
	}
	return m, nil
}

// WriteNonce sends the raw launch nonce as the first bytes on the data
// channel. ReadNonce verifies it against the nonce from the control
// handshake: both inherited descriptors then provably belong to the same
// supervisor launch, so a cross-wired spawn fails instead of silently
// attaching a foreign data channel to a network stack.
func WriteNonce(w io.Writer, nonce []byte) error {
	if len(nonce) != nonceLen {
		return fmt.Errorf("workerproto: nonce length %d", len(nonce))
	}
	_, err := w.Write(nonce)
	return err
}

// ReadNonce reads and validates the data-channel nonce.
func ReadNonce(r io.Reader, want []byte) error {
	got := make([]byte, nonceLen)
	if _, err := io.ReadFull(r, got); err != nil {
		return fmt.Errorf("workerproto: read nonce: %w", err)
	}
	if !bytes.Equal(got, want) {
		return fmt.Errorf("workerproto: data-channel nonce mismatch (cross-wired launch?)")
	}
	return nil
}

// Request is one supervisor→worker control call.
type Request struct {
	ID   uint64          `json:"id"`
	Op   string          `json:"op"`
	Body json.RawMessage `json:"body,omitempty"`
}

// Response is the worker's reply; ID always echoes the request.
type Response struct {
	ID    uint64          `json:"id"`
	OK    bool            `json:"ok"`
	Error string          `json:"error,omitempty"`
	Body  json.RawMessage `json:"body,omitempty"`
}

// Client is the supervisor's control endpoint. Calls are concurrent —
// a long-parked call (vm.wait) never blocks short operations — with
// request IDs monotonically increasing (the worker rejects anything
// else). Responses are matched by ID; a response for an abandoned call
// is dropped, not fatal.
type Client struct {
	conn net.Conn
	wmu  sync.Mutex // serializes request writes

	mu       sync.Mutex
	nextID   uint64
	pending  map[uint64]chan callResult
	stickyEr error // terminal transport error

	done     chan struct{} // closed when the read loop exits
	doneOnce sync.Once
	Timeout  time.Duration // bounds one call round-trip; zero = default
}

type callResult struct {
	resp Response
	err  error
}

// NewClient wraps an established control connection and starts its
// response-dispatch loop.
func NewClient(conn net.Conn) *Client {
	c := &Client{conn: conn, pending: map[uint64]chan callResult{}, done: make(chan struct{}), Timeout: 30 * time.Second}
	go c.readLoop()
	return c
}

// failAll terminates every outstanding and future call: a transport
// error ends the whole worker relationship (treated as worker death,
// never as a retryable operation failure).
func (c *Client) failAll(err error) {
	c.doneOnce.Do(func() {
		c.mu.Lock()
		c.stickyEr = err
		pending := c.pending
		c.pending = map[uint64]chan callResult{}
		c.mu.Unlock()
		for _, ch := range pending {
			ch <- callResult{err: err}
		}
		close(c.done)
	})
}

func (c *Client) readLoop() {
	for {
		var resp Response
		err := ReadMessage(c.conn, &resp)
		if err != nil {
			c.failAll(err)
			return
		}
		c.mu.Lock()
		ch, ok := c.pending[resp.ID]
		if ok {
			delete(c.pending, resp.ID)
		}
		maxIssued := c.nextID
		c.mu.Unlock()
		if ok {
			ch <- callResult{resp: resp}
			continue
		}
		// Not pending: either a stale response for an abandoned call
		// (resp.ID <= maxIssued — drop it) or an ID the client never
		// issued (worker bug — fatal to the channel).
		if resp.ID > maxIssued {
			c.failAll(fmt.Errorf("workerproto: response ID %d never issued (max %d)", resp.ID, maxIssued))
			return
		}
	}
}

// Call issues one request and waits for its response. A transport error
// is terminal for the worker relationship; a timeout abandons only this
// call (the late response is dropped when it arrives).
func (c *Client) Call(op string, body, out any) error {
	return c.CallWithTimeout(op, body, out, c.Timeout)
}

// CallWithTimeout is Call with an explicit per-call bound; zero uses the
// client default.
func (c *Client) CallWithTimeout(op string, body, out any, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := c.CallContext(ctx, op, body, out); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return fmt.Errorf("workerproto: call %q timed out after %s", op, timeout)
		}
		return err
	}
	return nil
}

// CallContext issues one request and waits without an implicit deadline.
// Canceling ctx abandons only this call; a late response is dropped. Closing
// the Client or losing the control connection still fails all calls.
func (c *Client) CallContext(ctx context.Context, op string, body, out any) error {
	var raw json.RawMessage
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		raw = b
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// ID assignment and the write are atomic under wmu: the worker
	// rejects non-increasing IDs, so wire order must match ID order
	// even with concurrent callers.
	c.wmu.Lock()
	if err := ctx.Err(); err != nil {
		c.wmu.Unlock()
		return err
	}
	c.mu.Lock()
	if c.stickyEr != nil {
		err := c.stickyEr
		c.mu.Unlock()
		c.wmu.Unlock()
		return err
	}
	c.nextID++
	id := c.nextID
	ch := make(chan callResult, 1)
	c.pending[id] = ch
	c.mu.Unlock()
	werr := WriteMessage(c.conn, Request{ID: id, Op: op, Body: raw})
	c.wmu.Unlock()
	if werr != nil {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return werr
	}
	select {
	case r := <-ch:
		if r.err != nil {
			return r.err
		}
		if !r.resp.OK {
			return fmt.Errorf("%s", r.resp.Error)
		}
		if out != nil && len(r.resp.Body) > 0 {
			return json.Unmarshal(r.resp.Body, out)
		}
		return nil
	case <-ctx.Done():
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return ctx.Err()
	}
}

// Close ends the control connection; outstanding calls fail.
func (c *Client) Close() error { return c.conn.Close() }

// Handler answers one request; returning an error produces a
// {ok:false,error} response. A panic is converted to the same shape so a
// bad request can never kill the serve loop's protocol state.
//
// Returning ErrShutdown is special: the worker sends an OK response (and
// encodes a non-nil body) before ServeRequests returns nil. This lets a
// graceful-stop op furnish final state while the reply is still guaranteed
// to reach the supervisor before the control channel unwinds.
type Handler func(req Request) (any, error)

// ErrShutdown: see Handler.
var ErrShutdown = errors.New("workerproto: graceful shutdown")

// ServeHandshake reads and validates the worker-side handshake, returning
// the role-specific bootstrap config. It installs the handshake deadline
// and clears it before returning.
func ServeHandshake(conn net.Conn, wantRole string, config any) ([]byte, error) {
	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))
	defer func() { _ = conn.SetDeadline(time.Time{}) }()
	var hs Handshake
	if err := ReadMessage(conn, &hs); err != nil {
		return nil, err
	}
	if hs.Magic != Magic {
		return nil, fmt.Errorf("workerproto: bad magic %q", hs.Magic)
	}
	if hs.Role != wantRole {
		return nil, fmt.Errorf("workerproto: bad role %q (want %q)", hs.Role, wantRole)
	}
	nonce, err := hex.DecodeString(hs.Nonce)
	if err != nil || len(nonce) != nonceLen {
		return nil, fmt.Errorf("workerproto: malformed nonce")
	}
	if config != nil {
		if len(hs.Config) == 0 {
			return nil, fmt.Errorf("workerproto: missing bootstrap config")
		}
		if err := json.Unmarshal(hs.Config, config); err != nil {
			return nil, fmt.Errorf("workerproto: bootstrap config: %w", err)
		}
	}
	return nonce, nil
}

// SendHandshake is the supervisor side of ServeHandshake: handshake first,
// then (separately) WriteNonce on the data channel.
func SendHandshake(conn net.Conn, role string, nonce []byte, config any) error {
	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))
	defer func() { _ = conn.SetDeadline(time.Time{}) }()
	raw, err := json.Marshal(config)
	if err != nil {
		return err
	}
	return WriteMessage(conn, Handshake{
		Magic:  Magic,
		Role:   role,
		Nonce:  hex.EncodeToString(nonce),
		Config: raw,
	})
}

// ServeOptions selects operations that must execute serially in wire order.
// Other operations remain concurrent, so a parked vm.wait cannot starve
// vm.close. OrderedOps is read-only for the duration of ServeRequests.
type ServeOptions struct {
	OrderedOps map[string]bool
}

// ServeRequests is the control-channel server loop (worker-side for the main
// channel and supervisor-side for the reverse bridge). It enforces strictly
// increasing request IDs and dispatches known ops; any protocol violation
// (oversized message, malformed JSON, duplicate/out-of-order ID, unknown
// op) terminates the loop with an error — fatal to the worker by design.
// A clean peer EOF returns nil so shutdown-by-close is not an error path.
//
// Handlers run concurrently, up to MaxConcurrentHandlers per connection, so
// a long-parked op like vm.wait cannot starve short ones. Further requests
// receive socket backpressure until a slot is released. Response order is
// arbitrary and matched by request ID; unordered handlers must protect shared
// state. A handler returning ErrShutdown gets its OK response (including any
// non-nil body) written first, then the loop returns nil — the graceful-stop
// reply is guaranteed to reach the peer.
func ServeRequests(conn net.Conn, ops map[string]Handler) error {
	return ServeRequestsWithOptions(conn, ops, ServeOptions{})
}

// ServeRequestsWithOptions is ServeRequests with optional wire-order
// serialization for related operations. All calls retain the same mandatory
// per-connection concurrency bound.
func ServeRequestsWithOptions(conn net.Conn, ops map[string]Handler, options ServeOptions) error {
	var lastID uint64
	var wmu sync.Mutex
	shutdown := make(chan struct{})
	var shutdownOnce sync.Once
	slots := make(chan struct{}, MaxConcurrentHandlers)
	orderedTail := make(chan struct{})
	close(orderedTail)
	for {
		select {
		case <-shutdown:
			return nil
		default:
		}
		var req Request
		err := ReadMessage(conn, &req)
		if err != nil {
			select {
			case <-shutdown:
				return nil // supervisor unwound after the OK response
			default:
			}
			if ne, ok := err.(interface{ Unwrap() error }); ok {
				if ue := ne.Unwrap(); ue == io.EOF || ue == io.ErrUnexpectedEOF {
					return nil
				}
			}
			return err
		}
		if req.ID == 0 || req.ID <= lastID {
			return fmt.Errorf("workerproto: request ID %d not increasing (last %d)", req.ID, lastID)
		}
		lastID = req.ID
		handler, ok := ops[req.Op]
		if !ok {
			return fmt.Errorf("workerproto: unknown op %q", req.Op)
		}
		select {
		case slots <- struct{}{}:
		case <-shutdown:
			return nil
		}
		var orderedAfter, orderedDone chan struct{}
		if options.OrderedOps[req.Op] {
			orderedAfter = orderedTail
			orderedDone = make(chan struct{})
			orderedTail = orderedDone
		}
		go func(req Request, handler Handler, orderedAfter, orderedDone chan struct{}) {
			defer func() { <-slots }()
			if orderedDone != nil {
				defer close(orderedDone)
				select {
				case <-orderedAfter:
				case <-shutdown:
					return
				}
				select {
				case <-shutdown:
					return
				default:
				}
			}
			body, herr := func() (out any, err error) {
				defer func() {
					if r := recover(); r != nil {
						err = fmt.Errorf("handler panic: %v", r)
					}
				}()
				return handler(req)
			}()
			if herr == ErrShutdown {
				resp := Response{ID: req.ID, OK: true}
				if body != nil {
					raw, err := json.Marshal(body)
					if err != nil {
						resp.OK = false
						resp.Error = fmt.Sprintf("workerproto: encode response for %q: %v", req.Op, err)
					} else {
						resp.Body = raw
					}
				}
				wmu.Lock()
				_ = WriteMessage(conn, resp)
				wmu.Unlock()
				shutdownOnce.Do(func() { close(shutdown) })
				// Unblock the read loop even if the supervisor lingers:
				// the OK is already delivered, the relationship is over.
				_ = conn.Close()
				return
			}
			resp := Response{ID: req.ID, OK: herr == nil}
			if herr != nil {
				resp.Error = herr.Error()
			} else if body != nil {
				raw, err := json.Marshal(body)
				if err != nil {
					resp.OK = false
					resp.Error = fmt.Sprintf("workerproto: encode response for %q: %v", req.Op, err)
				} else {
					resp.Body = raw
				}
			}
			wmu.Lock()
			_ = WriteMessage(conn, resp) // a dead conn ends the read loop next
			wmu.Unlock()
		}(req, handler, orderedAfter, orderedDone)
	}
}

// DecodeBody unmarshals a request body for handlers.
func DecodeBody(req Request, v any) error {
	if len(req.Body) == 0 {
		return fmt.Errorf("missing request body")
	}
	return json.Unmarshal(req.Body, v)
}
