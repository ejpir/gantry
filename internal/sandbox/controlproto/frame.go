package controlproto

import (
	"bufio"
	"errors"
	"fmt"
	"time"
)

const (
	// Control requests are commands and metadata, never bulk data. Session
	// bytes flow only after the bounded JSON handshake has completed.
	MaxRequestBytes  = 64 << 10
	MaxResponseBytes = 1 << 20
	MaxEventBytes    = 64 << 10
	HandshakeTimeout = 5 * time.Second
	OverloadTimeout  = time.Second
	CallTimeout      = 30 * time.Second
	ConfigureTimeout = 150 * time.Second // guest-helper delivery may use the bounded exec fallback
)

var ErrFrameTooLarge = errors.New("control frame too large")

// ReadBoundedLine reads one newline-terminated frame without allowing a peer
// to grow process memory without bound. The common case fits in bufio's
// existing buffer and does not allocate a second copy.
func ReadBoundedLine(r *bufio.Reader, maxBytes int) ([]byte, error) {
	if maxBytes <= 0 {
		return nil, fmt.Errorf("%w: invalid limit %d", ErrFrameTooLarge, maxBytes)
	}

	var line []byte
	for {
		fragment, err := r.ReadSlice('\n')
		if len(fragment) > maxBytes-len(line) {
			return nil, fmt.Errorf("%w: limit is %d bytes", ErrFrameTooLarge, maxBytes)
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

// Bounds on the CLI-to-daemon secrets handshake. It is a single JSON line on
// the session channel, so it needs its own limit: secret values are larger
// than a control request but still must not be unbounded.
const (
	SecretsHandshakeMaxBytes   = 1 << 20
	SecretsHandshakeMaxEntries = 256
)
