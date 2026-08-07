//go:build linux || darwin

package workerproto

import (
	"fmt"
	"net"
	"os"
	"syscall"
	"time"
)

// FD passing over a dedicated unix channel (SCM_RIGHTS). Runtime
// descriptor transfers — vsock dial bridging, share hot-add — correlate
// an RPC on the control channel with a descriptor on this one via a
// random token: the supervisor sends the descriptor with the token,
// the RPC handler waits for the matching token. Keeping transfers on
// their own channel means every message here is exactly one sendmsg
// with a fixed-size payload, so stream framing never splits or
// coalesces the rights-carrying byte range.
//
// Layout per message: FDTokenLen payload bytes (the token) + one fd.

// FDTokenLen is the byte length of a transfer token.
const FDTokenLen = 16

// fdRecvTimeout bounds one descriptor receive; the peer sends the fd
// immediately around the correlated RPC, so a longer wait is a bug.
const fdRecvTimeout = 10 * time.Second

// SendFD transfers fd with its correlation token in a single sendmsg.
func SendFD(conn net.Conn, token [FDTokenLen]byte, f *os.File) error {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("workerproto: fd passing needs a unix channel, got %T", conn)
	}
	oob := syscall.UnixRights(int(f.Fd()))
	if _, _, err := uc.WriteMsgUnix(token[:], oob, nil); err != nil {
		return fmt.Errorf("workerproto: send fd: %w", err)
	}
	return nil
}

// RecvFD receives one token + descriptor. The descriptor is already
// duplicated into this process by the kernel; it is independent of the
// sender's copy except for sharing the open file description (offset,
// locks) — which is exactly what the vsock bridge and share pinning
// rely on.
func RecvFD(conn net.Conn) ([FDTokenLen]byte, *os.File, error) {
	var token [FDTokenLen]byte
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return token, nil, fmt.Errorf("workerproto: fd passing needs a unix channel, got %T", conn)
	}
	_ = uc.SetReadDeadline(time.Now().Add(fdRecvTimeout))
	defer func() { _ = uc.SetReadDeadline(time.Time{}) }()
	oob := make([]byte, syscall.CmsgSpace(4))
	_, oobn, _, _, err := uc.ReadMsgUnix(token[:], oob)
	if err != nil {
		return token, nil, fmt.Errorf("workerproto: recv fd: %w", err)
	}
	cmsgs, err := syscall.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return token, nil, fmt.Errorf("workerproto: parse rights: %w", err)
	}
	for i := range cmsgs {
		fds, err := syscall.ParseUnixRights(&cmsgs[i])
		if err != nil {
			continue
		}
		if len(fds) > 0 {
			f := os.NewFile(uintptr(fds[0]), "workerproto-fd")
			for _, extra := range fds[1:] {
				_ = syscall.Close(extra)
			}
			return token, f, nil
		}
	}
	return token, nil, fmt.Errorf("workerproto: no descriptor in message")
}
