//go:build !windows

package sandbox

import (
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/term"
)

// forwardResizes follows the attached terminal: on each SIGWINCH it reports
// the new size to send. The returned function stops following.
func forwardResizes(send func(cols, rows uint32)) func() {
	changes := make(chan os.Signal, 1)
	signal.Notify(changes, syscall.SIGWINCH)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-done:
				return
			case <-changes:
				if cols, rows, err := term.GetSize(int(os.Stdout.Fd())); err == nil && cols > 0 && rows > 0 {
					send(uint32(cols), uint32(rows))
				}
			}
		}
	}()
	return func() {
		signal.Stop(changes)
		close(done)
	}
}
