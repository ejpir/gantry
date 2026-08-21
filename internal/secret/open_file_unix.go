//go:build !windows

package secret

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// openSecretFile uses O_NONBLOCK so a configured FIFO/device cannot wedge a
// broker worker in open(2). Only regular files are valid secret sources.
func openSecretFile(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("open %s returned an invalid descriptor", path)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	return file, nil
}
