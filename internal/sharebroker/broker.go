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
	shareBrokerMagic       = uint32(0x47534631) // "GSF1"
	shareBrokerVersion     = uint16(1)
	shareBrokerRequest     = uint16(1)
	shareBrokerResponse    = uint16(2)
	shareBrokerHeaderSize  = 32
	shareBrokerMaxIOVs     = 65 // matches Core.availChain's maximum
	shareBrokerMaxErrno    = 4095
	shareBrokerHeaderMagic = 0
	shareBrokerHeaderVer   = 4
	shareBrokerHeaderType  = 6
	shareBrokerHeaderID    = 8
	// MaxMessageBytes matches the virtio-fs descriptor-chain limit. Both
	// sides enforce it independently because either process may be hostile.
	MaxMessageBytes = 256 << 10
)

// Client forwards one ordered request at a time over a bounded byte stream.
// It contains no host path, directory descriptor, Windows handle, or virtio
// state.
type Client struct {
	rwc io.ReadWriteCloser

	callMu      sync.Mutex // one ordered request/response on the byte stream
	nextID      uint64
	header      [shareBrokerHeaderSize]byte
	lengths     [shareBrokerMaxIOVs]uint32
	wireLengths [shareBrokerMaxIOVs * 4]byte

	stateMu  sync.Mutex
	terminal error
	closeOne sync.Once
}

// NewClient takes ownership of rwc. The stream may be a Unix socketpair, a
// Windows named pipe, or any other reliable byte stream; the wire protocol has
// no OS-specific descriptor-passing requirement.
func NewClient(rwc io.ReadWriteCloser) (*Client, error) {
	if rwc == nil {
		return nil, fmt.Errorf("share broker client: nil transport")
	}
	return &Client{rwc: rwc}, nil
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
	defer func() { _ = rwc.Close() }()

	var lastID uint64
	var frame brokerFrame
	for {
		if _, err := io.ReadFull(rwc, frame.header[:]); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("share broker: read request header: %w", err)
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
		n, status, callErr := callFuseHandler(handler, in, out)
		if callErr != nil {
			return fmt.Errorf("share broker: request %d: %w", id, callErr)
		}
		// FUSE no-reply operations (notably FORGET/BATCH_FORGET) arrive
		// without writable descriptors. go-fuse may still report the size
		// of its internal response header; the direct virtio frontend has
		// always discarded that value when no output buffer exists. Keep
		// the broker transport behavior identical instead of rejecting a
		// valid request as a response-capacity violation.
		if len(outLens) == 0 {
			n = 0
		}
		if status != fuse.OK {
			n = 0
		} else if n < 0 || uint64(n) > sumBrokerLens(outLens) {
			return fmt.Errorf("share broker: request %d returned %d bytes for %d-byte output", id, n, sumBrokerLens(outLens))
		}
		payload := frame.output[:n]
		if err := writeShareBrokerResponse(rwc, id, status, payload, &frame.header); err != nil {
			return fmt.Errorf("share broker: request %d response: %w", id, err)
		}
	}
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

	if err := c.terminalError(); err != nil {
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
	if err := writeShareBrokerRequest(c.rwc, id, inLens, outLens, in, &c.header, &c.wireLengths); err != nil {
		c.fail(err)
		return 0, fuse.EIO
	}

	if _, err := io.ReadFull(c.rwc, c.header[:]); err != nil {
		c.fail(fmt.Errorf("share broker: read response header: %w", err))
		return 0, fuse.EIO
	}
	status, n, err := parseShareBrokerResponse(c.header[:], id, sumBrokerLens(outLens))
	if err != nil {
		c.fail(err)
		return 0, fuse.EIO
	}
	if status != fuse.OK {
		return 0, status
	}
	if err := readBrokerOutput(c.rwc, out, int(n)); err != nil {
		c.fail(fmt.Errorf("share broker: read response payload: %w", err))
		return 0, fuse.EIO
	}
	return int(n), fuse.OK
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
	c.closeOne.Do(func() { _ = c.rwc.Close() })
}

func (c *Client) Close() error {
	c.stateMu.Lock()
	if c.terminal == nil {
		c.terminal = io.ErrClosedPipe
	}
	c.stateMu.Unlock()
	var err error
	c.closeOne.Do(func() { err = c.rwc.Close() })
	return err
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

func writeShareBrokerRequest(w io.Writer, id uint64, inLens, outLens []uint32, in [][]byte, header *[shareBrokerHeaderSize]byte, table *[shareBrokerMaxIOVs * 4]byte) error {
	clear(header[:])
	putShareBrokerHeader(header[:], shareBrokerRequest, id)
	binary.BigEndian.PutUint16(header[16:18], uint16(len(inLens)))
	binary.BigEndian.PutUint16(header[18:20], uint16(len(outLens)))
	binary.BigEndian.PutUint32(header[20:24], uint32(sumBrokerLens(inLens)))
	binary.BigEndian.PutUint32(header[24:28], uint32(sumBrokerLens(outLens)))
	if err := writeBrokerAll(w, header[:]); err != nil {
		return fmt.Errorf("share broker: write request header: %w", err)
	}
	lengths := table[:4*(len(inLens)+len(outLens))]
	for i, n := range inLens {
		binary.BigEndian.PutUint32(lengths[i*4:], n)
	}
	offset := 4 * len(inLens)
	for i, n := range outLens {
		binary.BigEndian.PutUint32(lengths[offset+i*4:], n)
	}
	if err := writeBrokerAll(w, lengths); err != nil {
		return fmt.Errorf("share broker: write IOV lengths: %w", err)
	}
	for _, b := range in {
		if err := writeBrokerAll(w, b); err != nil {
			return fmt.Errorf("share broker: write input: %w", err)
		}
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
	header      [shareBrokerHeaderSize]byte
	lengths     [shareBrokerMaxIOVs]uint32
	wireLengths [shareBrokerMaxIOVs * 4]byte
	input       []byte
	output      []byte
	inIOV       [shareBrokerMaxIOVs][]byte
	outIOV      [shareBrokerMaxIOVs][]byte
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

func writeShareBrokerResponse(w io.Writer, id uint64, status fuse.Status, payload []byte, header *[shareBrokerHeaderSize]byte) error {
	clear(header[:])
	putShareBrokerHeader(header[:], shareBrokerResponse, id)
	binary.BigEndian.PutUint32(header[16:20], uint32(int32(status)))
	binary.BigEndian.PutUint32(header[20:24], uint32(len(payload)))
	binary.BigEndian.PutUint32(header[24:28], uint32(len(payload)))
	if err := writeBrokerAll(w, header[:]); err != nil {
		return err
	}
	return writeBrokerAll(w, payload)
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

func readBrokerOutput(r io.Reader, out [][]byte, size int) error {
	remaining := size
	for _, part := range out {
		if remaining == 0 {
			return nil
		}
		if len(part) > remaining {
			part = part[:remaining]
		}
		if _, err := io.ReadFull(r, part); err != nil {
			return err
		}
		remaining -= len(part)
	}
	if remaining != 0 {
		return io.ErrUnexpectedEOF
	}
	return nil
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
