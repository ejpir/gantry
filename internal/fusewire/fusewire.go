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

	// MaxNotificationBytes bounds the Gantry virtio-fs notification extension.
	// INVAL_ENTRY is below 512 bytes and batched PRUNE notifications fit in 8
	// KiB. Both the guest driver and every host transport enforce this limit.
	MaxNotificationBytes = 8 << 10
)

// NotificationSink accepts one complete FUSE notification frame. The frame is
// call-scoped; sinks that retain it must copy it. Status is a Linux FUSE errno.
type NotificationSink func(message []byte) fuse.Status

// NotificationSource is implemented by a FUSE protocol endpoint capable of
// emitting reverse invalidations. A transport attaches the sink only after the
// guest has negotiated and populated Gantry's notification virtqueue. A nil
// sink detaches it and forces cache policy back to its short-TTL fallback.
type NotificationSource interface {
	SetNotificationSink(NotificationSink)
}

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

// ValidNotification validates an unsolicited FUSE response before a transport
// copies it into guest memory. Only the invalidation forms Gantry emits are
// accepted; STORE/RETRIEVE would turn this cache-coherence channel into a
// general host-to-guest memory writer.
func ValidNotification(message []byte) bool {
	if len(message) < outHeaderSize || len(message) > MaxNotificationBytes ||
		int(binary.LittleEndian.Uint32(message[0:4])) != len(message) ||
		binary.LittleEndian.Uint64(message[8:16]) != 0 {
		return false
	}
	code := int32(binary.LittleEndian.Uint32(message[4:8]))
	switch code {
	case -2: // FUSE_NOTIFY_INVAL_INODE
		return len(message) == outHeaderSize+24
	case -3: // FUSE_NOTIFY_INVAL_ENTRY
		if len(message) < outHeaderSize+16+1 {
			return false
		}
		nameLen := int(binary.LittleEndian.Uint32(message[outHeaderSize+8 : outHeaderSize+12]))
		return nameLen > 0 && len(message) == outHeaderSize+16+nameLen+1 && message[len(message)-1] == 0
	case -6: // FUSE_NOTIFY_DELETE
		if len(message) < outHeaderSize+24+1 {
			return false
		}
		nameLen := int(binary.LittleEndian.Uint32(message[outHeaderSize+16 : outHeaderSize+20]))
		return nameLen > 0 && len(message) == outHeaderSize+24+nameLen+1 && message[len(message)-1] == 0
	case -8: // FUSE_NOTIFY_INC_EPOCH
		return len(message) == outHeaderSize
	case -9: // FUSE_NOTIFY_PRUNE
		if len(message) < outHeaderSize+16 {
			return false
		}
		count := uint64(binary.LittleEndian.Uint32(message[outHeaderSize : outHeaderSize+4]))
		return count <= (MaxNotificationBytes-outHeaderSize-16)/8 &&
			uint64(len(message)) == uint64(outHeaderSize+16)+count*8
	default:
		return false
	}
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
