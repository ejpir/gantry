//go:build windows

// GANTRY PATCH: protocol debugging must compile without Unix open flag
// constants. Keep the representation simple on Windows.
package fuse

import "fmt"

func Print(obj any) string { return fmt.Sprintf("%+v", obj) }
