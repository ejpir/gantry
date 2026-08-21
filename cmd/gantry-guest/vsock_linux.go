//go:build linux

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/unix"

	"github.com/ejpir/gantry/internal/sandbox/credhelper/credproto"
)

// askBroker queries the host credential broker over vsock: the guest
// connects to the broker port and the VMM bridges the connection to the
// daemon's unix listener. One JSON line out, one JSON line back.
//
// Raw-fd I/O on purpose: importing "net" (for net.FileConn) would grow
// the guest binary by several MiB, and it streams into the VM on every
// boot of a sandbox with bound secrets. SO_RCVTIMEO/SNDTIMEO give the
// deadline semantics net.Conn would have.
func askBroker(host, path string) (credproto.Response, error) {
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return credproto.Response{}, fmt.Errorf("vsock socket: %w", err)
	}
	if err := unix.Connect(fd, &unix.SockaddrVM{CID: unix.VMADDR_CID_HOST, Port: credproto.VsockPort}); err != nil {
		_ = unix.Close(fd)
		return credproto.Response{}, fmt.Errorf("vsock connect (cid=host port=%d): %w", credproto.VsockPort, err)
	}
	tv := unix.NsecToTimeval(int64(credproto.ConnTimeout + time.Second)) // slack over the broker's own deadline
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		debugf("SO_RCVTIMEO: %v", err)
	}
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_SNDTIMEO, &tv); err != nil {
		debugf("SO_SNDTIMEO: %v", err)
	}
	f := os.NewFile(uintptr(fd), "vsock")
	defer func() { _ = f.Close() }()

	req, err := json.Marshal(credproto.Request{Host: host, Path: path})
	if err != nil {
		return credproto.Response{}, err
	}
	if _, err := f.Write(append(req, '\n')); err != nil {
		return credproto.Response{}, fmt.Errorf("write request: %w", err)
	}
	line, err := readLineBounded(f, credproto.MaxResponseBytes)
	if err != nil {
		return credproto.Response{}, fmt.Errorf("read response: %w", err)
	}
	var resp credproto.Response
	if err := json.Unmarshal(line, &resp); err != nil {
		return credproto.Response{}, fmt.Errorf("malformed broker response: %w", err)
	}
	return resp, nil
}

// readLineBounded reads one '\n'-terminated line, refusing more than max
// bytes. Local to the guest so cmd/gantry-guest needs no controlproto
// import (which would drag in the control plane's dependency tree).
func readLineBounded(f *os.File, max int) ([]byte, error) {
	var line []byte
	buf := make([]byte, 512)
	for {
		n, err := f.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			for i, b := range chunk {
				if b == '\n' {
					return append(line, chunk[:i]...), nil
				}
			}
			line = append(line, chunk...)
			if len(line) > max {
				return nil, fmt.Errorf("response exceeds %d bytes", max)
			}
		}
		if err != nil {
			return nil, err
		}
	}
}
