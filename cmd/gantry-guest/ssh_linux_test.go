//go:build linux

package main

import (
	"strconv"
	"strings"
	"testing"
)

func TestLookupGuestUserParsesPasswdWithoutGetent(t *testing.T) {
	root, err := lookupGuestUser("root")
	if err != nil {
		t.Fatal(err)
	}
	if root.UID != 0 || root.Name != "root" || root.Shell == "" {
		t.Fatalf("root lookup = %#v", root)
	}
	if _, err := lookupGuestUser("gantry-user-that-does-not-exist"); err == nil {
		t.Fatal("unknown user was accepted")
	}
}

func TestSupplementaryGroupsAcceptFullUint32GIDRange(t *testing.T) {
	if strconv.IntSize < 64 {
		t.Skip("guest targets use 64-bit int")
	}
	groups := parseSupplementaryGroups(strings.NewReader(strings.Join([]string{
		"primary:x:1000:gantry",
		"large:x:2147483648:gantry,other",
		"duplicate:x:2147483648:gantry",
		"too-large:x:4294967296:gantry",
		"unrelated:x:4000000000:other",
	}, "\n")), guestUser{Name: "gantry", GID: 1000})
	if len(groups) != 1 || int64(groups[0]) != int64(1)<<31 {
		t.Fatalf("supplementary groups = %v, want [2147483648]", groups)
	}
}

func TestTCPRelayRejectsNonLoopbackBeforeDial(t *testing.T) {
	if status := runTCPRelay([]string{"8.8.8.8", "53"}); status != 1 {
		t.Fatalf("non-loopback status = %d, want 1", status)
	}
	if status := runTCPRelay([]string{"127.0.0.2", "80"}); status != 1 {
		t.Fatalf("127/8 alias status = %d, want 1", status)
	}
}
