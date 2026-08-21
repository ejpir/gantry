//go:build !windows

package oauthtokens

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestRegistryRejectsPreplantedTokenEndpoints(t *testing.T) {
	for _, endpoint := range []string{"symlink", "fifo"} {
		t.Run(endpoint, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "oauth-tokens.json")
			switch endpoint {
			case "symlink":
				target := filepath.Join(dir, "target")
				if err := os.WriteFile(target, []byte("[]"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := syscall.Mkfifo(path, 0o600); err != nil {
					t.Fatal(err)
				}
			}

			r := New()
			r.AttachFile(dir)
			done := make(chan struct{})
			go func() {
				_ = r.Providers()
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("token registry blocked on a preplanted endpoint")
			}
			if _, err := os.Lstat(path); !os.IsNotExist(err) {
				t.Fatalf("unsafe endpoint was not quarantined: %v", err)
			}
		})
	}
}
