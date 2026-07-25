//go:build darwin

package main

import (
	"os"
	"syscall"
	"unsafe"
)

// darwin termios: tcflag_t = u64, NCCS = 20, plus ispeed/ospeed.
const (
	tiocgeta = 0x40487413
	tiocseta = 0x80487414
	icanon   = 0x100
	echo     = 0x8
)

type termios struct {
	Iflag, Oflag, Cflag, Lflag uint64
	Cc                         [20]byte
	Ispeed, Ospeed             uint64
}

var saved *termios

func setRawMode() {
	var t termios
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, os.Stdin.Fd(), tiocgeta, uintptr(unsafe.Pointer(&t)))
	if errno != 0 {
		return
	}
	saved = &t
	raw := t
	raw.Lflag &^= icanon | echo
	syscall.Syscall(syscall.SYS_IOCTL, os.Stdin.Fd(), tiocseta, uintptr(unsafe.Pointer(&raw)))
}

func restoreMode() {
	if saved != nil {
		syscall.Syscall(syscall.SYS_IOCTL, os.Stdin.Fd(), tiocseta, uintptr(unsafe.Pointer(saved)))
	}
}
