//go:build !windows

package sandbox

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestAuditPersistenceRejectsPreplantedEndpoints(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	auditPath := filepath.Join(dir, "audit.log")
	if err := os.Symlink(target, auditPath); err != nil {
		t.Fatal(err)
	}
	br := &broker{dir: dir}
	br.persistAuditLine("must not follow")
	got, err := os.ReadFile(target)
	if err != nil || string(got) != "unchanged" {
		t.Fatalf("audit symlink target = %q, %v", got, err)
	}

	if err := os.Remove(auditPath); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(auditPath, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		br.persistAuditLine("must not block")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("audit persistence blocked on a FIFO")
	}
}
