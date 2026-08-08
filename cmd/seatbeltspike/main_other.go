//go:build !darwin

package main

import (
	"fmt"
	"os"
	"runtime"
)

func main() {
	fmt.Fprintf(os.Stderr, "seatbeltspike: macOS-only probe (this is %s/%s)\n", runtime.GOOS, runtime.GOARCH)
	os.Exit(2)
}
