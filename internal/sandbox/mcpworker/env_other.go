//go:build !linux && !darwin && !windows

package mcpworker

func workerEnvironment() []string { return []string{} }
