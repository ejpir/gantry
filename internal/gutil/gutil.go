// Package gutil holds the tiny helpers shared by gantry's internal packages.
package gutil

import (
	"fmt"
	"os"
	"strings"
)

// EnvOr returns the first non-empty environment variable value. Used to
// accept the old MINIVM_* names after the rename to gantry.
func EnvOr(names ...string) string {
	for _, n := range names {
		if v := os.Getenv(n); v != "" {
			return v
		}
	}
	return ""
}

// InsertExtraCmdline inserts GANTRY_EXTRA_CMDLINE (MINIVM_ fallback) into a
// kernel cmdline BEFORE any " -- " init-args separator, so the extra args
// reach the kernel rather than vminitd. Used for debug knobs like
// hung_task_panic=1.
func InsertExtraCmdline(cmdline string) string {
	extra := EnvOr("GANTRY_EXTRA_CMDLINE", "MINIVM_EXTRA_CMDLINE")
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

// FileExists reports whether path exists on the host.
func FileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}
