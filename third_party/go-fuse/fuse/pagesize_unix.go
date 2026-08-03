//go:build !windows

package fuse

import "syscall"

func hostPageSize() int { return syscall.Getpagesize() }
