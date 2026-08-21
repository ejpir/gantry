//go:build linux

package main

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"
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
	} else {
		if os.Geteuid() != uid || os.Getegid() != gid {
			return fmt.Errorf("already running as %d:%d; cannot honor requested %d:%d", os.Geteuid(), os.Getegid(), uid, gid)
		}
		groups, err := os.Getgroups()
		if err != nil {
			return fmt.Errorf("inspect supplementary groups: %w", err)
		}
		for _, group := range groups {
			if group != gid {
				return fmt.Errorf("already running with supplementary group %d; cannot guarantee the requested identity", group)
			}
		}
	}
	return nil
}

func resolveUser(name string) (uid, gid int, err error) {
	if uidText, gidText, explicitGroup := strings.Cut(name, ":"); explicitGroup {
		if strings.Contains(gidText, ":") {
			return 0, 0, fmt.Errorf("user %q must be NAME, UID, or UID:GID", name)
		}
		uid64, uidErr := strconv.ParseUint(uidText, 10, 32)
		gid64, gidErr := strconv.ParseUint(gidText, 10, 32)
		if uidErr != nil || gidErr != nil {
			return 0, 0, fmt.Errorf("user %q must use a numeric UID:GID pair", name)
		}
		return int(uid64), int(gid64), nil
	}
	var (
		u    *user.User
		err2 error
	)
	if _, numericErr := strconv.ParseUint(name, 10, 32); numericErr == nil {
		u, err2 = user.LookupId(name)
	} else {
		u, err2 = user.Lookup(name)
	}
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
