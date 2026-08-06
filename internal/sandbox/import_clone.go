package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
)

// cloneImportedRWLayer creates Gantry's private writable-layer image.
// cloneFile is a platform-specific copy-on-write clone where available;
// the destination is published atomically so an interrupted import never
// leaves a partial ext4 image at the persistent path.
func cloneImportedRWLayer(source, destination string) error {
	if _, err := os.Stat(destination); err == nil {
		return fmt.Errorf("%s already exists (delete the existing Gantry sandbox first, or import with --as)", destination)
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(destination), ".import-rwlayer-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}
	// cloneFile expects to create its destination itself.
	if err := os.Remove(tmpPath); err != nil {
		return err
	}
	defer os.Remove(tmpPath)
	if err := cloneFile(source, tmpPath); err != nil {
		return err
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		return err
	}
	// Link, rather than Rename, gives publication no-replace semantics even
	// if another importer creates destination after the Stat above.
	return os.Link(tmpPath, destination)
}
