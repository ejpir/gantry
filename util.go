package main

import (
	"os"
	"strings"
)

// PSTATE at boot: EL1h (0b0101), all exceptions masked (D A I F = 0x3c0).
const pstateEL1hMask = 0x3c5

// envOr returns the first non-empty environment variable value. Used to
// accept the old MINIVM_* names after the rename to gantry.
func envOr(names ...string) string {
	for _, n := range names {
		if v := os.Getenv(n); v != "" {
			return v
		}
	}
	return ""
}

// insertExtraCmdline inserts GANTRY_EXTRA_CMDLINE (MINIVM_ fallback) into a
// kernel cmdline BEFORE any " -- " init-args separator, so the extra args
// reach the kernel rather than vminitd. Used for debug knobs like
// hung_task_panic=1.
func insertExtraCmdline(cmdline string) string {
	extra := envOr("GANTRY_EXTRA_CMDLINE", "MINIVM_EXTRA_CMDLINE")
	if extra == "" {
		return cmdline
	}
	if i := strings.Index(cmdline, " -- "); i >= 0 {
		return cmdline[:i] + " " + extra + cmdline[i:]
	}
	return cmdline + " " + extra
}

func le32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}
func le64(b []byte) uint64 {
	return uint64(le32(b)) | uint64(le32(b[4:]))<<32
}
