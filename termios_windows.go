//go:build windows

package main

// Console raw mode for interactive `run` on Windows: disable line input,
// echo and Ctrl-C processing on stdin; restore on exit.

import (
	"os"

	"golang.org/x/sys/windows"
)

var savedConsoleMode uint32
var consoleWasRaw bool

func setRawMode() {
	h := windows.Handle(os.Stdin.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(h, &mode); err != nil {
		return // not a console (piped input works as-is)
	}
	savedConsoleMode = mode
	const (
		enableEchoInput      = 0x0004
		enableLineInput      = 0x0002
		enableProcessedInput = 0x0001
	)
	raw := mode &^ (enableEchoInput | enableLineInput | enableProcessedInput)
	if err := windows.SetConsoleMode(h, raw); err == nil {
		consoleWasRaw = true
	}
}

func restoreMode() {
	if consoleWasRaw {
		windows.SetConsoleMode(windows.Handle(os.Stdin.Fd()), savedConsoleMode)
	}
}
