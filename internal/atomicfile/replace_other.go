//go:build !windows

package atomicfile

import (
	"errors"
	"os"
)

func openCommittedForSync(path string) (*os.File, error) { return os.Open(path) }

func replace(from, to string, _ bool) error {
	return os.Rename(from, to)
}

func syncParent(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(dir.Sync(), dir.Close())
}
