//go:build !windows

package selfupdate

import (
	"fmt"
	"os"

	"github.com/ejpir/gantry/internal/atomicfile"
)

func installStaged(staged, target string, _ int) (bool, error) {
	if err := os.Rename(staged, target); err != nil {
		return false, fmt.Errorf("replace Gantry executable %s: %w", target, err)
	}
	if err := atomicfile.MakeDurable(target); err != nil {
		return false, err
	}
	return false, nil
}

// Finish is the hidden Windows replacement helper entry point.
func Finish(string, string, int) error {
	return fmt.Errorf("deferred update completion is only used on Windows")
}
