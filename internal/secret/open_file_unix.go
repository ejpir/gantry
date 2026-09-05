//go:build !windows

package secret

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// openSecretFile walks an absolute path one descriptor at a time with
// O_NOFOLLOW. A different sandbox may have written any host directory it was
// explicitly shared, so pathname history cannot establish that a symlink is
// trusted. Pinning every parent also closes rename/symlink races between a
// check and the final open. O_NONBLOCK keeps FIFOs/devices from wedging a
// broker worker; only single-link regular files are valid sources.
func openSecretFile(path string) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, fmt.Errorf("secret file path must be absolute and clean: %q", path)
	}
	parts := strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))
	if len(parts) == 0 || (len(parts) == 1 && parts[0] == "") {
		return nil, fmt.Errorf("secret file path names a directory: %q", path)
	}
	dirfd, err := unix.Open(string(filepath.Separator), unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NONBLOCK|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	for _, component := range parts[:len(parts)-1] {
		next, openErr := unix.Openat(dirfd, component, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NONBLOCK|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
		_ = unix.Close(dirfd)
		if openErr != nil {
			return nil, fmt.Errorf("open symlink-free secret path component %q: %w", component, openErr)
		}
		dirfd = next
	}
	fd, err := unix.Openat(dirfd, parts[len(parts)-1], unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NONBLOCK|unix.O_NOFOLLOW, 0)
	_ = unix.Close(dirfd)
	if err != nil {
		return nil, fmt.Errorf("open symlink-free secret file: %w", err)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if stat.Nlink != 1 {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("%s has multiple hard links and is not a safe secret source", path)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("open %s returned an invalid descriptor", path)
	}
	return file, nil
}
