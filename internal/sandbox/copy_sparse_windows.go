//go:build windows

package sandbox

import (
	"io"
	"os"
)

// copySparse copies the image; Windows gets a plain full copy (holes are
// not preserved, but correctness is identical).
func copySparse(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
