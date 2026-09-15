//go:build windows

package sshconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenSSHCommandPathUsesUnquotedAbsoluteToken(t *testing.T) {
	longPath := filepath.Join(t.TempDir(), "gantry helper.exe")
	if err := os.WriteFile(longPath, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := OpenSSHCommandPath(longPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(got, " \t\"'") || !filepath.IsAbs(got) {
		t.Fatalf("OpenSSHCommandPath = %q, want an unquoted absolute token", got)
	}
	longInfo, err := os.Stat(longPath)
	if err != nil {
		t.Fatal(err)
	}
	shortInfo, err := os.Stat(got)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(longInfo, shortInfo) {
		t.Fatalf("short path %q does not identify %q", got, longPath)
	}
}
