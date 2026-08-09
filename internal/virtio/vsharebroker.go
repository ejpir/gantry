//go:build linux || darwin || windows

package virtio

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/ejpir/gantry/internal/gutil"

	"github.com/hanwen/go-fuse/v2/fuse"
)

// The share broker protocol carries exactly one FUSE request/response at a
// time. The current virtio-mmio frontend is synchronous too, so serializing the
// stream preserves its ordering while placing a hard, connection-wide bound on
// allocations. It is deliberately binary: FUSE reads and writes are the hot
// path, and JSON would base64-expand every payload.
const (
	shareBrokerMagic        = uint32(0x47534631) // "GSF1"
	shareBrokerVersion      = uint16(1)
	shareBrokerRequest      = uint16(1)
	shareBrokerResponse     = uint16(2)
	shareBrokerHeaderSize   = 32
	shareBrokerMaxIOVs      = 65 // matches Core.availChain's maximum
	shareBrokerMaxErrno     = 4095
	shareBrokerMaxLiveNodes = 64 << 10
	shareBrokerHeaderMagic  = 0
	shareBrokerHeaderVer    = 4
	shareBrokerHeaderType   = 6
	shareBrokerHeaderID     = 8
)

// ShareHubProxy is the VMM-side virtio-fs device. It contains no host path,
// directory descriptor, or Windows handle: raw FUSE request IOVs cross a
// bounded stream to the supervisor-owned ShareHub instead.
type ShareHubProxy struct {
	*fsTransportDevice
	client *shareBrokerClient
}

// NewShareHubProxy takes ownership of rwc. The stream may be a Unix
// socketpair, a Windows named pipe, or any other reliable byte stream; the wire
// protocol has no OS-specific descriptor-passing requirement.
func NewShareHubProxy(rwc io.ReadWriteCloser) (*ShareHubProxy, error) {
	if rwc == nil {
		return nil, fmt.Errorf("share hub proxy: nil transport")
	}
	client := &shareBrokerClient{rwc: rwc}
	debug := gutil.EnvOr("GANTRY_DEBUG_FS", "MINIVM_DEBUG_FS") != ""
	return &ShareHubProxy{
		fsTransportDevice: newFSTransportDevice(shareHubTag, client, debug),
		client:            client,
	}, nil
}

// Tag is the virtio-fs mount tag advertised to the guest.
func (p *ShareHubProxy) Tag() string { return shareHubTag }

// VirtioDevice returns the MMIO frontend without transferring ownership of
// the broker stream to Machine.Close. In split mode a guest exit closes all
// ordinary devices, but the worker control loop must keep this relay alive
// long enough to report vm.wait; runVMMWorker closes the owning proxy when
// that loop itself unwinds.
func (p *ShareHubProxy) VirtioDevice() Device { return p.fsTransportDevice }

// Close interrupts an in-flight broker request and releases the stream.
func (p *ShareHubProxy) Close() error {
	if p == nil || p.client == nil {
		return nil
	}
	return p.client.Close()
}

var _ Device = (*ShareHubProxy)(nil)
var _ io.Closer = (*ShareHubProxy)(nil)

// ServeBroker serves one ShareHubProxy until the peer closes the stream or a
// malformed frame is received. It takes ownership of rwc but not h. Callers
// must treat a protocol error as a fatal VMM-worker error; retrying a stateful
// FUSE request could repeat a host mutation.
func (h *ShareHub) ServeBroker(rwc io.ReadWriteCloser) error {
	if h == nil || h.handler == nil {
		return fmt.Errorf("share broker: nil hub")
	}
	if rwc == nil {
		return fmt.Errorf("share broker: nil transport")
	}
	defer func() { _ = rwc.Close() }()

	var lastID uint64
	handleLimit := shareBrokerHandleLimit()
	for {
		var hdr [shareBrokerHeaderSize]byte
		if _, err := io.ReadFull(rwc, hdr[:]); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("share broker: read request header: %w", err)
		}
		id, inLens, outLens, err := readShareBrokerRequest(rwc, hdr[:], lastID)
		if err != nil {
			return fmt.Errorf("share broker: %w", err)
		}
		lastID = id

		in, err := readBrokerInput(rwc, inLens)
		if err != nil {
			return fmt.Errorf("share broker: request %d input: %w", id, err)
		}
		out := makeBrokerIOV(outLens)
		n, status, callErr := callFuseHandler(h.handler, in, out)
		if callErr != nil {
			return fmt.Errorf("share broker: request %d: %w", id, callErr)
		}
		if reporter, ok := h.handler.(interface {
			GantryResourceUsage() (nodes, handles int)
		}); ok {
			nodes, handles := reporter.GantryResourceUsage()
			if handles > handleLimit {
				return fmt.Errorf("share broker: request %d exceeded live handle limit (%d > %d)", id, handles, handleLimit)
			}
			if nodes > shareBrokerMaxLiveNodes {
				return fmt.Errorf("share broker: request %d exceeded live inode limit (%d > %d)", id, nodes, shareBrokerMaxLiveNodes)
			}
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
		payload := flattenBrokerPrefix(out, n)
		if err := writeShareBrokerResponse(rwc, id, status, payload); err != nil {
			return fmt.Errorf("share broker: request %d response: %w", id, err)
		}
	}
}

// callFuseHandler turns a parser/backend panic into a fatal broker protocol
// error. The broker lives in the trusted supervisor, so malformed guest input
// must never unwind that process.
func callFuseHandler(handler fuseRequestHandler, in, out [][]byte) (n int, status fuse.Status, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("FUSE handler panic: %v", recovered)
		}
	}()
	n, status = handler.HandleRequest(in, out)
	return n, status, nil
}

type shareBrokerClient struct {
	rwc io.ReadWriteCloser

	callMu sync.Mutex // one ordered request/response on the byte stream
	nextID uint64

	stateMu  sync.Mutex
	terminal error
	closeOne sync.Once
}

func (c *shareBrokerClient) HandleRequest(in, out [][]byte) (int, fuse.Status) {
	c.callMu.Lock()
	defer c.callMu.Unlock()

	if err := c.terminalError(); err != nil {
		return 0, fuse.EIO
	}
	inLens, outLens, err := validateBrokerIOV(in, out)
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
	if err := writeShareBrokerRequest(c.rwc, id, inLens, outLens, in); err != nil {
		c.fail(err)
		return 0, fuse.EIO
	}

	var hdr [shareBrokerHeaderSize]byte
	if _, err := io.ReadFull(c.rwc, hdr[:]); err != nil {
		c.fail(fmt.Errorf("share broker: read response header: %w", err))
		return 0, fuse.EIO
	}
	status, n, err := parseShareBrokerResponse(hdr[:], id, sumBrokerLens(outLens))
	if err != nil {
		c.fail(err)
		return 0, fuse.EIO
	}
	if status != fuse.OK {
		return 0, status
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(c.rwc, payload); err != nil {
		c.fail(fmt.Errorf("share broker: read response payload: %w", err))
		return 0, fuse.EIO
	}
	scatterBrokerPrefix(out, payload)
	return int(n), fuse.OK
}

func (c *shareBrokerClient) terminalError() error {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	return c.terminal
}

func (c *shareBrokerClient) fail(err error) {
	c.stateMu.Lock()
	if c.terminal == nil {
		c.terminal = err
	}
	c.stateMu.Unlock()
	c.closeOne.Do(func() { _ = c.rwc.Close() })
}

func (c *shareBrokerClient) Close() error {
	c.stateMu.Lock()
	if c.terminal == nil {
		c.terminal = io.ErrClosedPipe
	}
	c.stateMu.Unlock()
	var err error
	c.closeOne.Do(func() { err = c.rwc.Close() })
	return err
}

func validateBrokerIOV(in, out [][]byte) ([]uint32, []uint32, error) {
	if len(in) == 0 {
		return nil, nil, fmt.Errorf("share broker: request has no input IOV")
	}
	if len(in)+len(out) > shareBrokerMaxIOVs {
		return nil, nil, fmt.Errorf("share broker: %d IOVs exceed cap %d", len(in)+len(out), shareBrokerMaxIOVs)
	}
	inLens := make([]uint32, len(in))
	outLens := make([]uint32, len(out))
	var total uint64
	for i, b := range in {
		inLens[i] = uint32(len(b))
		total += uint64(len(b))
	}
	for i, b := range out {
		outLens[i] = uint32(len(b))
		total += uint64(len(b))
	}
	if total > fsMaxChainBytes {
		return nil, nil, fmt.Errorf("share broker: IOV bytes %d exceed cap %d", total, fsMaxChainBytes)
	}
	return inLens, outLens, nil
}

func writeShareBrokerRequest(w io.Writer, id uint64, inLens, outLens []uint32, in [][]byte) error {
	var hdr [shareBrokerHeaderSize]byte
	putShareBrokerHeader(hdr[:], shareBrokerRequest, id)
	binary.BigEndian.PutUint16(hdr[16:18], uint16(len(inLens)))
	binary.BigEndian.PutUint16(hdr[18:20], uint16(len(outLens)))
	binary.BigEndian.PutUint32(hdr[20:24], uint32(sumBrokerLens(inLens)))
	binary.BigEndian.PutUint32(hdr[24:28], uint32(sumBrokerLens(outLens)))
	if err := writeBrokerAll(w, hdr[:]); err != nil {
		return fmt.Errorf("share broker: write request header: %w", err)
	}
	lengths := make([]byte, 4*(len(inLens)+len(outLens)))
	for i, n := range append(append([]uint32(nil), inLens...), outLens...) {
		binary.BigEndian.PutUint32(lengths[i*4:], n)
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

func readShareBrokerRequest(r io.Reader, hdr []byte, lastID uint64) (uint64, []uint32, []uint32, error) {
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
	if wantIn+wantOut > fsMaxChainBytes {
		return 0, nil, nil, fmt.Errorf("request bytes %d exceed cap %d", wantIn+wantOut, fsMaxChainBytes)
	}

	table := make([]byte, 4*(inCount+outCount))
	if _, err := io.ReadFull(r, table); err != nil {
		return 0, nil, nil, fmt.Errorf("read IOV lengths: %w", err)
	}
	inLens := make([]uint32, inCount)
	outLens := make([]uint32, outCount)
	for i := range inLens {
		inLens[i] = binary.BigEndian.Uint32(table[i*4:])
	}
	for i := range outLens {
		outLens[i] = binary.BigEndian.Uint32(table[(inCount+i)*4:])
	}
	if sumBrokerLens(inLens) != wantIn || sumBrokerLens(outLens) != wantOut {
		return 0, nil, nil, fmt.Errorf("IOV lengths do not match declared totals")
	}
	return id, inLens, outLens, nil
}

func readBrokerInput(r io.Reader, lens []uint32) ([][]byte, error) {
	total := sumBrokerLens(lens)
	payload := make([]byte, int(total))
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	out := make([][]byte, len(lens))
	off := 0
	for i, n := range lens {
		out[i] = payload[off : off+int(n)]
		off += int(n)
	}
	return out, nil
}

func makeBrokerIOV(lens []uint32) [][]byte {
	out := make([][]byte, len(lens))
	for i, n := range lens {
		out[i] = make([]byte, int(n))
	}
	return out
}

func writeShareBrokerResponse(w io.Writer, id uint64, status fuse.Status, payload []byte) error {
	var hdr [shareBrokerHeaderSize]byte
	putShareBrokerHeader(hdr[:], shareBrokerResponse, id)
	binary.BigEndian.PutUint32(hdr[16:20], uint32(int32(status)))
	binary.BigEndian.PutUint32(hdr[20:24], uint32(len(payload)))
	binary.BigEndian.PutUint32(hdr[24:28], uint32(len(payload)))
	if err := writeBrokerAll(w, hdr[:]); err != nil {
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
	if n != payloadLen || uint64(n) > outCap || uint64(n) > fsMaxChainBytes {
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

func flattenBrokerPrefix(iov [][]byte, n int) []byte {
	if n <= 0 {
		return nil
	}
	out := make([]byte, n)
	off := 0
	for _, b := range iov {
		if off == n {
			break
		}
		off += copy(out[off:], b)
	}
	return out
}

func scatterBrokerPrefix(iov [][]byte, payload []byte) {
	off := 0
	for _, b := range iov {
		if off == len(payload) {
			return
		}
		off += copy(b, payload[off:])
	}
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
