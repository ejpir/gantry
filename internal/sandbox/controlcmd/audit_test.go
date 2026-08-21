package controlcmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ejpir/gantry/internal/sandbox/layout"
)

func TestAuditTailFallsBackToPersistedLog(t *testing.T) {
	home := t.TempDir()
	t.Setenv("GANTRY_HOME", home)
	dir := filepath.Join(layout.Root(), "demo")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	lines := "mcp: session open\nmcp: call fs__read_file\n"
	if err := os.WriteFile(filepath.Join(dir, "audit.log"), []byte(lines), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := AuditTail("demo") // no daemon: must read audit.log, not fail on ctl.sock
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "mcp: session open" {
		t.Fatalf("persisted tail = %v", got)
	}
}
