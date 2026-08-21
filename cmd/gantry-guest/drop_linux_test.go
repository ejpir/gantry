//go:build linux

package main

import "testing"

func TestResolveUserAcceptsExplicitNumericUIDGID(t *testing.T) {
	uid, gid, err := resolveUser("1234:5678")
	if err != nil || uid != 1234 || gid != 5678 {
		t.Fatalf("resolveUser explicit pair = %d:%d, %v", uid, gid, err)
	}
	for _, malformed := range []string{"1234:", ":5678", "1234:group", "1:2:3"} {
		if _, _, err := resolveUser(malformed); err == nil {
			t.Errorf("resolveUser(%q) succeeded", malformed)
		}
	}
}
