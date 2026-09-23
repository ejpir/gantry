//go:build windows

package sandbox

// forwardResizes is a no-op on Windows, which has no SIGWINCH; sessions keep
// the size they started with.
func forwardResizes(func(cols, rows uint32)) func() { return func() {} }
