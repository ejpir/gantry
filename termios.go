//go:build linux

package main

import (
	"os"
	"syscall"
	"unsafe"
)

// Minimal termios handling so the guest shell sees raw keystrokes.
// Skipped silently when stdin isn't a TTY (piped input works as-is).

const (
	tcgets = 0x5401
	tcsets = 0x5402
)

type termios struct {
	Iflag, Oflag, Cflag, Lflag uint32
	Line                       byte
	Cc                         [19]byte
}

var saved *termios

func setRawMode() {
	var t termios
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, os.Stdin.Fd(), tcgets, uintptr(unsafe.Pointer(&t)))
	if errno != 0 {
		return // not a tty
	}
	saved = &t
	raw := t
	raw.Lflag &^= 0x2 | 0x8 // ICANON | ECHO
	raw.Iflag &^= 0x1       // BRKINT-ish minimal: keep simple
	syscall.Syscall(syscall.SYS_IOCTL, os.Stdin.Fd(), tcsets, uintptr(unsafe.Pointer(&raw)))
}

func restoreMode() {
	if saved != nil {
		syscall.Syscall(syscall.SYS_IOCTL, os.Stdin.Fd(), tcsets, uintptr(unsafe.Pointer(saved)))
	}
}
