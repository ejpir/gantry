//go:build !windows

package main

import "fmt"

func runTerminalBridge(string) (int, error) {
	return 1, fmt.Errorf("the terminal bridge is only available on Windows")
}
