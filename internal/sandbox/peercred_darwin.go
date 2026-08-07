//go:build darwin

package sandbox

import (
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// peerUID reports the effective UID at the other end of a unix-domain
// connection — answered by the kernel (LOCAL_PEERCRED Xucred), not by
// anything the peer claims.
func peerUID(c net.Conn) (uint32, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return 0, fmt.Errorf("not a unix connection: %T", c)
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *unix.Xucred
	var serr error
	if err := raw.Control(func(fd uintptr) {
		cred, serr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if serr != nil {
		return 0, serr
	}
	return cred.Uid, nil
}

// peerSameUser reports whether the process at the other end of c runs
// under the same user account as this daemon. ctl.sock carries no
// authentication beyond this: the trust domain is the user account (any
// same-UID process could present any credential we could issue, so a
// token or TLS would add ceremony, not security) — this check exists so
// a misconfigured or relocated socket directory can never silently open
// the broker to OTHER local users. Note macOS ignores permission bits on
// the socket inode itself; the 0700 directory and this check do the work.
func peerSameUser(c net.Conn) bool {
	uid, err := peerUID(c)
	return err == nil && int(uid) == os.Geteuid()
}
