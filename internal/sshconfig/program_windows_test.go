//go:build windows

package sshconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenSSHProgramSelectsNativeWindowsClient(t *testing.T) {
	for _, name := range []string{"ssh", "sftp"} {
		path, err := OpenSSHProgram(name)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.EqualFold(filepath.Base(filepath.Dir(path)), "OpenSSH") || !strings.EqualFold(filepath.Base(path), name+".exe") {
			t.Fatalf("OpenSSHProgram(%q) = %q, want native Windows OpenSSH", name, path)
		}
		if info, err := os.Stat(path); err != nil || !info.Mode().IsRegular() {
			t.Fatalf("OpenSSHProgram(%q) does not name a regular file: %v", name, err)
		}
	}
}
