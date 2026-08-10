// Package gutil holds the tiny helpers shared by gantry's internal packages.
package gutil

import (
	"fmt"
	"os"
	"strings"
)

// InsertExtraCmdline inserts GANTRY_EXTRA_CMDLINE into a kernel cmdline before
// any " -- " init-args separator, so the extra args reach the kernel rather
// than vminitd. It is used for debug knobs such as hung_task_panic=1.
func InsertExtraCmdline(cmdline string) string {
	extra := os.Getenv("GANTRY_EXTRA_CMDLINE")
	if extra == "" {
		return cmdline
	}
	if i := strings.Index(cmdline, " -- "); i >= 0 {
		return cmdline[:i] + " " + extra + cmdline[i:]
	}
	return cmdline + " " + extra
}

// LE32/LE64 decode little-endian values from the front of b (truncating or
// zero-padding short slices would hide bugs; callers guarantee len).
func LE32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

func LE64(b []byte) uint64 {
	return uint64(LE32(b)) | uint64(LE32(b[4:]))<<32
}

// strList is a repeatable string flag.
type StrList []string

func (s *StrList) String() string { return fmt.Sprint([]string(*s)) }
func (s *StrList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

// List returns the accumulated values.
func (s *StrList) List() []string { return []string(*s) }

// FileExists reports whether path exists on the host.
func FileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}

// HumanSize renders bytes for progress output.
func HumanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := int64(unit), 0
	for x := n / unit; x >= unit; x /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%c", float64(n)/float64(div), "KMGTPE"[exp])
}
