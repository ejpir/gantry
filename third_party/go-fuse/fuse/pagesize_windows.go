//go:build windows

package fuse

func hostPageSize() int { return 4096 }
