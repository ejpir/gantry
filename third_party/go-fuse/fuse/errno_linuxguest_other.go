//go:build !darwin && !windows

package fuse

import "syscall"

func hostErrnoToLinux(e syscall.Errno) Status { return Status(e) }
