//go:build windows

package sandbox

import (
	"context"
	"errors"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

const handshakeWriteRetry = time.Millisecond

func writeDaemonHandshake(ctx context.Context, handshake *os.File, payload string) error {
	// os.Pipe uses a synchronous anonymous pipe on Windows. Closing that handle
	// from another goroutine does not interrupt a blocked WriteFile. Switching
	// only the parent's write handle to PIPE_NOWAIT lets this loop observe
	// cancellation while preserving the inherited reader's blocking behavior.
	mode := uint32(windows.PIPE_NOWAIT)
	if err := windows.SetNamedPipeHandleState(windows.Handle(handshake.Fd()), &mode, nil, nil); err != nil {
		return errors.Join(ctx.Err(), err, handshake.Close())
	}

	remaining := []byte(payload)
	var writeErr error
	for len(remaining) != 0 {
		if err := ctx.Err(); err != nil {
			break
		}
		var written uint32
		writeErr = windows.WriteFile(windows.Handle(handshake.Fd()), remaining, &written, nil)
		if written != 0 {
			remaining = remaining[written:]
		}
		if writeErr != nil {
			break
		}
		if written != 0 {
			continue
		}
		timer := time.NewTimer(handshakeWriteRetry)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
		case <-timer.C:
		}
	}
	closeErr := handshake.Close()
	return errors.Join(ctx.Err(), writeErr, closeErr)
}
