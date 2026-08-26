//go:build !windows

package sshgw

import (
	"os"
	"testing"
)

func assertPrivateHostKey(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("host key mode = %o, want 600", info.Mode().Perm())
	}
}
