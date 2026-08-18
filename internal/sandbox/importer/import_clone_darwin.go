//go:build darwin

package importer

import "golang.org/x/sys/unix"

func cloneFile(source, destination string) error {
	return unix.Clonefile(source, destination, 0)
}
