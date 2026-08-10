package workerproto

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

const (
	// MaxMessage caps one JSON control message, excluding its length prefix.
	MaxMessage = 1 << 20
	// MaxFrame matches the largest Ethernet frame accepted by virtio-net.
	MaxFrame = 65562
)

// Request is one supervisor-to-worker control call.
type Request struct {
	ID   uint64          `json:"id"`
	Op   string          `json:"op"`
	Body json.RawMessage `json:"body,omitempty"`
}

// Response is the worker's reply. ID always echoes the request.
type Response struct {
	ID    uint64          `json:"id"`
	OK    bool            `json:"ok"`
	Error string          `json:"error,omitempty"`
	Body  json.RawMessage `json:"body,omitempty"`
}

// messageWriter owns reusable control-frame storage. Callers serialize access
// to one writer, avoiding the header+body append allocation on every message.
type messageWriter struct {
	buffer []byte
}

func (writer *messageWriter) writeMessage(w io.Writer, value any) error {
	body, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(body) > MaxMessage {
		return fmt.Errorf("workerproto: message %d bytes > cap %d", len(body), MaxMessage)
	}

	size := 4 + len(body)
	if cap(writer.buffer) < size {
		writer.buffer = make([]byte, size)
	} else {
		writer.buffer = writer.buffer[:size]
	}
	binary.BigEndian.PutUint32(writer.buffer[:4], uint32(len(body)))
	copy(writer.buffer[4:], body)
	if err := writeOnce(w, writer.buffer); err != nil {
		return fmt.Errorf("workerproto: write: %w", err)
	}
	return nil
}

// WriteMessage frames one JSON control message. Client and server connections
// retain their own writer; this convenience function is for one-off messages
// such as boot acknowledgements and handshakes.
func WriteMessage(w io.Writer, value any) error {
	var writer messageWriter
	return writer.writeMessage(w, value)
}

// messageReader retains bounded input storage for one serialized read stream.
type messageReader struct {
	buffer []byte
}

func (reader *messageReader) readMessage(r io.Reader, value any) error {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return fmt.Errorf("workerproto: read header: %w", err)
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > MaxMessage {
		return fmt.Errorf("workerproto: message length %d out of bounds", size)
	}

	if cap(reader.buffer) < int(size) {
		reader.buffer = make([]byte, size)
	} else {
		reader.buffer = reader.buffer[:size]
	}
	if _, err := io.ReadFull(r, reader.buffer); err != nil {
		return fmt.Errorf("workerproto: read body: %w", err)
	}
	if err := json.Unmarshal(reader.buffer, value); err != nil {
		return fmt.Errorf("workerproto: decode: %w", err)
	}
	return nil
}

// ReadMessage reads one framed JSON control message. Lengths are validated
// before allocating storage.
func ReadMessage(r io.Reader, value any) error {
	var reader messageReader
	return reader.readMessage(r, value)
}

// WriteFrame writes one QEMU-framed Ethernet frame on the data channel.
func WriteFrame(w io.Writer, frame []byte) error {
	if err := validateFrameLength(len(frame)); err != nil {
		return err
	}
	framed := make([]byte, 4+len(frame))
	binary.BigEndian.PutUint32(framed[:4], uint32(len(frame)))
	copy(framed[4:], frame)
	if err := writeOnce(w, framed); err != nil {
		return fmt.Errorf("workerproto: write frame: %w", err)
	}
	return nil
}

// FrameWriter reuses one bounded header+payload buffer across a frame stream.
// A network pump owns one writer, keeping steady-state traffic allocation-free.
type FrameWriter struct {
	buffer [4 + MaxFrame]byte
}

func (writer *FrameWriter) WriteFrame(w io.Writer, frame []byte) error {
	if err := validateFrameLength(len(frame)); err != nil {
		return err
	}
	binary.BigEndian.PutUint32(writer.buffer[:4], uint32(len(frame)))
	copy(writer.buffer[4:], frame)
	payload := writer.buffer[:4+len(frame)]
	written, err := w.Write(payload)
	if err != nil {
		return fmt.Errorf("workerproto: write frame: %w", err)
	}
	if written != len(payload) {
		return fmt.Errorf("workerproto: write frame: %w", io.ErrShortWrite)
	}
	return nil
}

func validateFrameLength(size int) error {
	if size == 0 || size > MaxFrame {
		return fmt.Errorf("workerproto: frame length %d out of bounds", size)
	}
	return nil
}

// ReadFrame reads one QEMU-framed Ethernet frame into caller-owned storage.
func ReadFrame(r io.Reader, buffer []byte) (int, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return 0, err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > MaxFrame || int(size) > len(buffer) {
		return 0, fmt.Errorf("workerproto: frame length %d out of bounds", size)
	}
	return io.ReadFull(r, buffer[:size])
}

// writeOnce preserves frame atomicity on transports that implement it. A
// short write corrupts framing and is therefore terminal rather than resumed.
func writeOnce(w io.Writer, payload []byte) error {
	written, err := w.Write(payload)
	if err != nil {
		return err
	}
	if written != len(payload) {
		return io.ErrShortWrite
	}
	return nil
}
