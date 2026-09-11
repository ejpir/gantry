//go:build !linux

package main

import (
	"fmt"
	"os"
)

func runOAuthWatch([]string) int {
	fmt.Fprintln(os.Stderr, "gantry-guest: oauth-watch is only available inside a Linux guest")
	return 1
}
