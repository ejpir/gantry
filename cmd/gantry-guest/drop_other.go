//go:build !linux

package main

import "fmt"

// dropToUser stub: mcp-serve only runs inside the guest VM.
func dropToUser(string) error {
	return fmt.Errorf("mcp-serve is only supported inside a gantry guest")
}
