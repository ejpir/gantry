//go:build !linux && !darwin && !windows

package vmmworker

import (
	"fmt"
	"os"
)

// Main refuses the hidden worker role on platforms without descriptor passing.
func Main() int {
	fmt.Fprintln(os.Stderr, "vmm worker unsupported on this platform")
	return 2
}
