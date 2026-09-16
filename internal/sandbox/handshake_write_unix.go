//go:build !windows

package sandbox

import (
	"context"
	"errors"
	"io"
	"os"
)

func writeDaemonHandshake(ctx context.Context, handshake *os.File, payload string) error {
	stop := context.AfterFunc(ctx, func() { _ = handshake.Close() })
	defer stop()
	written, writeErr := io.WriteString(handshake, payload)
	if writeErr == nil && written != len(payload) {
		writeErr = io.ErrShortWrite
	}
	closeErr := handshake.Close()
	return errors.Join(ctx.Err(), writeErr, closeErr)
}
