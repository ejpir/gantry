// Package fusewire defines the raw FUSE request boundary shared by the host
// filesystem service, broker transport, and virtio frontend.
package fusewire

import (
	"encoding/binary"

	"github.com/hanwen/go-fuse/v2/fuse"
)

const (
	// InHeaderSize is sizeof(struct fuse_in_header). Every FUSE request starts
	// with this header. The protocol server joins at most the first two input
	// vectors before parsing it, so transports must apply the same rule when
	// validating guest-controlled IOV shapes.
	InHeaderSize  = 40
	outHeaderSize = 16
)

// Handler consumes one raw FUSE request and fills the supplied response
// vectors. Implementations return the response length and a transport status.
// The vectors are call-scoped and must not be retained after HandleRequest
// returns; transports reuse their backing storage between requests.
type Handler interface {
	HandleRequest(in, out [][]byte) (int, fuse.Status)
}

// ValidRequest reports whether the parser can read a complete FUSE input
// header from the vectors it joins. It deliberately validates only framing;
// opcode-specific sizes remain the protocol server's responsibility.
func ValidRequest(in [][]byte) bool {
	available := 0
	for _, part := range in[:min(len(in), 2)] {
		available += len(part)
	}
	return available >= InHeaderSize
}

// CopyPrefix copies the leading bytes of an IOV into dst without allocating.
func CopyPrefix(dst []byte, iov [][]byte) int {
	written := 0
	for _, part := range iov {
		written += copy(dst[written:], part)
		if written == len(dst) {
			break
		}
	}
	return written
}

// WriteError serializes a FUSE error response, including when the writable
// header spans multiple descriptors. It returns zero when capacity is too
// small for a complete response; partial protocol headers are never emitted.
func WriteError(in, out [][]byte, status fuse.Status) int {
	if !ValidRequest(in) || iovLen(out) < outHeaderSize {
		return 0
	}
	var header [outHeaderSize]byte
	binary.LittleEndian.PutUint32(header[0:4], outHeaderSize)
	binary.LittleEndian.PutUint32(header[4:8], uint32(-int32(status)))
	var request [outHeaderSize]byte
	CopyPrefix(request[:], in)
	copy(header[8:16], request[8:16])
	writePrefix(out, header[:])
	return len(header)
}

func iovLen(iov [][]byte) int {
	total := 0
	for _, part := range iov {
		total += len(part)
	}
	return total
}

func writePrefix(iov [][]byte, src []byte) {
	read := 0
	for _, part := range iov {
		read += copy(part, src[read:])
		if read == len(src) {
			return
		}
	}
}
