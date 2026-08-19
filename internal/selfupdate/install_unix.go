//go:build !windows

package selfupdate

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ejpir/gantry/internal/atomicfile"
)

func installStaged(_ context.Context, staged, target string) error {
	if err := os.Rename(staged, target); err != nil {
		return fmt.Errorf("replace Gantry executable %s: %w", target, err)
	}
	return atomicfile.MakeDurable(target)
}

func createStagedFile(target string) (*os.File, error) {
	return os.CreateTemp(filepath.Dir(target), "."+filepath.Base(target)+".update-*")
}

func cleanupRetired(string) error { return nil }
