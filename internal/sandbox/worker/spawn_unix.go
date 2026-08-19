//go:build linux || darwin

package worker

import (
	"fmt"
	"net"
	"os"
	"syscall"
)

// socketpairConn returns both ends of an AF_UNIX SOCK_STREAM socketpair
// as net.Conns (the portable baseline for the worker channels;
// SOCK_SEQPACKET is a documented benchmark candidate, not a requirement).
func SocketpairConns() (a, b net.Conn, err error) {
	// Socketpair has no portable atomic CLOEXEC flag across Linux and Darwin.
	// Exclude a concurrent fork/exec until both raw descriptors are marked so
	// an unrelated child can never inherit a worker channel capability.
	syscall.ForkLock.RLock()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err == nil {
		syscall.CloseOnExec(fds[0])
		syscall.CloseOnExec(fds[1])
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		return nil, nil, fmt.Errorf("socketpair: %w", err)
	}
	mk := func(fd int, name string) (net.Conn, error) {
		f := os.NewFile(uintptr(fd), name)
		defer func() { _ = f.Close() }()
		return net.FileConn(f)
	}
	a, err = mk(fds[0], "socketpair-a")
	if err != nil {
		_ = syscall.Close(fds[1])
		return nil, nil, err
	}
	b, err = mk(fds[1], "socketpair-b")
	if err != nil {
		_ = a.Close()
		return nil, nil, err
	}
	return a, b, nil
}

// ConnFile extracts a dup'd *os.File from a socket net.Conn.
func ConnFile(c net.Conn) (*os.File, error) {
	type filer interface{ File() (*os.File, error) }
	f, ok := c.(filer)
	if !ok {
		return nil, fmt.Errorf("conn %T cannot expose its fd", c)
	}
	return f.File()
}

// DupConnFiles transfers ownership of conns to this helper, closes every
// source connection, and returns the duplicated files needed by ExtraFiles.
// A partial failure also closes every duplicate already created.
func DupConnFiles(conns ...net.Conn) ([]*os.File, error) {
	files := make([]*os.File, 0, len(conns))
	defer func() {
		for _, c := range conns {
			if c != nil {
				_ = c.Close()
			}
		}
	}()
	for i, c := range conns {
		f, fileErr := ConnFile(c)
		if fileErr != nil {
			CloseFiles(files)
			return nil, fmt.Errorf("connection %d: %w", i, fileErr)
		}
		files = append(files, f)
	}
	return files, nil
}
