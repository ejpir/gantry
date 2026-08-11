//go:build linux || darwin

package sandbox

import (
	"fmt"
	"os"
)

// newSharedRAM creates an anonymous-by-unlink file object suitable for mapping
// guest RAM MAP_SHARED in both the VMM and a vhost-style filesystem backend.
// The object never has a reusable pathname: only explicitly transferred
// descriptors can map it.
func newSharedRAM(dir string, size uint64) (*os.File, error) {
	if size == 0 || size > uint64(^uint64(0)>>1) {
		return nil, fmt.Errorf("shared guest RAM: invalid size %d", size)
	}
	file, err := os.CreateTemp(dir, ".gantry-guest-ram-*")
	if err != nil {
		return nil, fmt.Errorf("create shared guest RAM: %w", err)
	}
	name := file.Name()
	removeErr := os.Remove(name)
	if removeErr != nil {
		_ = file.Close()
		return nil, fmt.Errorf("unlink shared guest RAM: %w", removeErr)
	}
	if err := file.Truncate(int64(size)); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("size shared guest RAM: %w", err)
	}
	return file, nil
}
