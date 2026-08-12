//go:build !windows

package vmm

func platformKernelArgs(cmdline, _ string) (string, error) { return cmdline, nil }
