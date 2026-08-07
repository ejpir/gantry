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
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const (
	// Magic identifies protocol version 1 of the control handshake.
	Magic = "GANTRY-WORKER/1"
	// RoleNet is the only worker role implemented so far (Phase 1 of the
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

// Client is the supervisor's synchronous control endpoint. Calls are
// serialized: one outstanding request at a time, IDs monotonically
// increasing (the worker rejects anything else).
type Client struct {
	conn   net.Conn
	mu     sync.Mutex
	nextID uint64
	// Timeout bounds one full call round-trip; zero uses the default.
	Timeout time.Duration
}

// NewClient wraps an established control connection.
func NewClient(conn net.Conn) *Client { return &Client{conn: conn, Timeout: 30 * time.Second} }

// Call issues one request and waits for its response. A transport error
// is terminal for the worker relationship; callers treat it as worker
// death, not as a retryable operation failure.
func (c *Client) Call(op string, body, out any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.nextID++
	id := c.nextID
	req := Request{ID: id, Op: op}
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		req.Body = raw
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	_ = c.conn.SetDeadline(time.Now().Add(timeout))
	defer func() { _ = c.conn.SetDeadline(time.Time{}) }()
	if err := WriteMessage(c.conn, req); err != nil {
		return err
	}
	var resp Response
	if err := ReadMessage(c.conn, &resp); err != nil {
		return err
	}
	if resp.ID != id {
		return fmt.Errorf("workerproto: response ID %d does not match request %d", resp.ID, id)
	}
	if !resp.OK {
		return fmt.Errorf("%s", resp.Error)
	}
	if out != nil && len(resp.Body) > 0 {
		return json.Unmarshal(resp.Body, out)
	}
	return nil
}

// Close ends the control connection.
func (c *Client) Close() error { return c.conn.Close() }

// Handler answers one request; returning an error produces a
// {ok:false,error} response. A panic is converted to the same shape so a
// bad request can never kill the serve loop's protocol state.
type Handler func(req Request) (any, error)

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

// ServeRequests is the worker-side control loop. It enforces strictly
// increasing request IDs and dispatches known ops; any protocol violation
// (oversized message, malformed JSON, duplicate/out-of-order ID, unknown
// op) terminates the loop with an error — fatal to the worker by design.
// A clean peer EOF returns nil so shutdown-by-close is not an error path.
func ServeRequests(conn net.Conn, ops map[string]Handler) error {
	var lastID uint64
	for {
		var req Request
		err := ReadMessage(conn, &req)
		if err != nil {
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
		body, herr := func() (out any, err error) {
			defer func() {
				if r := recover(); r != nil {
					err = fmt.Errorf("handler panic: %v", r)
				}
			}()
			return handler(req)
		}()
		resp := Response{ID: req.ID, OK: herr == nil}
		if herr != nil {
			resp.Error = herr.Error()
		} else if body != nil {
			raw, err := json.Marshal(body)
			if err != nil {
				return fmt.Errorf("workerproto: encode response for %q: %w", req.Op, err)
			}
			resp.Body = raw
		}
		if err := WriteMessage(conn, resp); err != nil {
			return err
		}
	}
}

// DecodeBody unmarshals a request body for handlers.
func DecodeBody(req Request, v any) error {
	if len(req.Body) == 0 {
		return fmt.Errorf("missing request body")
	}
	return json.Unmarshal(req.Body, v)
}
