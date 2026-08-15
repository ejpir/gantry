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
