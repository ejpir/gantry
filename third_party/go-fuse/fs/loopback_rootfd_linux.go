//go:build linux

package fs

import "path/filepath"

// Linux resolves the pinned /proc/self/fd path dynamically. The result is the
// underlying directory's current path, so traversal follows renames without
// retargeting a replacement at the original path.
func loopbackRootFDPath(_ int, fallback string) string {
	resolved, err := filepath.EvalSymlinks(fallback)
	if err != nil {
		return fallback
	}
	return resolved
}
