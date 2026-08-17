//go:build !windows

package selfupdate

import (
	"fmt"
	"os"

	"github.com/ejpir/gantry/internal/atomicfile"
)

func installStaged(staged, target string) error {
	if err := os.Rename(staged, target); err != nil {
		return fmt.Errorf("replace Gantry executable %s: %w", target, err)
	}
	return atomicfile.MakeDurable(target)
}
