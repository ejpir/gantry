//go:build !darwin

package importer

import (
	"io"
	"os"
)

// The reference sandbox store currently exists on macOS, where clonefile
// gives us an instantaneous APFS copy-on-write clone. Keep other targets
// buildable and correct if a compatible store is supplied explicitly.
func cloneFile(source, destination string) (retErr error) {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		if err := out.Close(); retErr == nil {
			retErr = err
		}
	}()
	if _, retErr = io.Copy(out, in); retErr != nil {
		return retErr
	}
	// The caller publishes destination with os.Link right after we return:
	// without an fsync the copied bytes may still be page-cache-only, so a
	// machine crash after publication could expose a zero-length/partial
	// ext4 image at the persistent path.
	retErr = out.Sync()
	return retErr
}
