//go:build windows

// GANTRY PATCH: protocol debugging must compile without Unix open flag
// constants. Keep the representation simple on Windows.
package fuse

import "fmt"

// %#v deliberately bypasses String methods. Several FUSE structs implement
// String by calling Print, so the ordinary %v family recurses until the host
// process exhausts its stack when protocol debugging is enabled.
func Print(obj any) string { return fmt.Sprintf("%#v", obj) }
