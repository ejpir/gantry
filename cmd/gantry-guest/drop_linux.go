//go:build linux

package main

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"syscall"
)

// dropToUser resolves name (or numeric uid) and setgid/setuids to it.
// Refusing to run as root is a hard rule (docs/mcp-gateway.md): a
// filesystem server with the exec channel's root privileges would make
// guest confinement meaningless.
func dropToUser(name string) error {
	if name == "" {
		return fmt.Errorf("--user is required (refusing to run as root)")
	}
	uid, gid, err := resolveUser(name)
	if err != nil {
		return err
	}
	if uid == 0 {
		return fmt.Errorf("user %q resolves to uid 0: refusing to run as root", name)
	}
	if os.Geteuid() == 0 {
		if err := syscall.Setgroups([]int{}); err != nil {
			return fmt.Errorf("setgroups: %w", err)
		}
		if err := syscall.Setgid(gid); err != nil {
			return fmt.Errorf("setgid %d: %w", gid, err)
		}
		if err := syscall.Setuid(uid); err != nil {
			return fmt.Errorf("setuid %d: %w", uid, err)
		}
		if os.Geteuid() != uid {
			return fmt.Errorf("privilege drop did not take effect (euid %d, want %d)", os.Geteuid(), uid)
		}
	} else if os.Geteuid() != uid {
		// Already unprivileged (tests, direct invocation): serve as the
		// current user rather than fail, but say so on stderr.
		fmt.Fprintf(os.Stderr, "gantry-guest mcp-serve: not root; serving as uid %d (wanted %d)\n", os.Geteuid(), uid)
	}
	return nil
}

func resolveUser(name string) (uid, gid int, err error) {
	if n, err2 := strconv.Atoi(name); err2 == nil {
		return n, n, nil
	}
	u, err2 := user.Lookup(name)
	if err2 != nil {
		return 0, 0, fmt.Errorf("user %q not found in the guest: %w", name, err2)
	}
	uid, err = strconv.Atoi(u.Uid)
	if err != nil {
		return 0, 0, fmt.Errorf("user %q: bad uid %q", name, u.Uid)
	}
	gid, err = strconv.Atoi(u.Gid)
	if err != nil {
		return 0, 0, fmt.Errorf("user %q: bad gid %q", name, u.Gid)
	}
	return uid, gid, nil
}
