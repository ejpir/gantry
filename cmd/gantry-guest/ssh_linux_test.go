//go:build linux

package main

import "testing"

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

func TestTCPRelayRejectsNonLoopbackBeforeDial(t *testing.T) {
	if status := runTCPRelay([]string{"8.8.8.8", "53"}); status != 1 {
		t.Fatalf("non-loopback status = %d, want 1", status)
	}
	if status := runTCPRelay([]string{"127.0.0.2", "80"}); status != 1 {
		t.Fatalf("127/8 alias status = %d, want 1", status)
	}
}
