package sandbox

import (
	"bufio"
	"errors"
	"fmt"
	"time"
)

const (
	// Control requests are commands and metadata, never bulk data. Session
	// bytes flow only after the bounded JSON handshake has completed.
	controlMaxRequestBytes  = 64 << 10
	controlMaxResponseBytes = 1 << 20
	controlMaxEventBytes    = 64 << 10
	controlHandshakeTimeout = 5 * time.Second
	controlOverloadTimeout  = time.Second
	controlCallTimeout      = 30 * time.Second
)

var errControlFrameTooLarge = errors.New("control frame too large")

// readBoundedLine reads one newline-terminated frame without allowing a peer
// to grow process memory without bound. The common case fits in bufio's
// existing buffer and does not allocate a second copy.
func readBoundedLine(r *bufio.Reader, maxBytes int) ([]byte, error) {
	if maxBytes <= 0 {
		return nil, fmt.Errorf("%w: invalid limit %d", errControlFrameTooLarge, maxBytes)
	}

	var line []byte
	for {
		fragment, err := r.ReadSlice('\n')
		if len(fragment) > maxBytes-len(line) {
			return nil, fmt.Errorf("%w: limit is %d bytes", errControlFrameTooLarge, maxBytes)
		}
		if len(line) == 0 && err == nil {
			return fragment, nil
		}
		line = append(line, fragment...)
		if err == nil {
			return line, nil
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			return line, err
		}
	}
}
