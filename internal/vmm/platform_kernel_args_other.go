//go:build !windows

package vmm

func platformKernelArgs(cmdline, _ string, _ uint64) (string, error) { return cmdline, nil }
