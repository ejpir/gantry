//go:build !linux && !darwin && !windows

package sharefs

import (
	"fmt"
	"os"
	"path/filepath"
)

func identifyRoot(path string) (Identity, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return Identity{}, err
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return Identity{}, err
	}
	if !info.IsDir() {
		return Identity{}, fmt.Errorf("not a directory: %s", resolved)
	}
	// Unsupported hosts have no live share backend. A path-only identity is
	// sufficient for validating restart configuration there.
	return Identity{path: filepath.Clean(resolved), valid: true}, nil
}
