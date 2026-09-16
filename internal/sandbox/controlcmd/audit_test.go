package controlcmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

func TestPersistedAuditTailBoundsAndFileType(t *testing.T) {
	t.Setenv("GANTRY_HOME", t.TempDir())
	if err := os.MkdirAll(layout.Dir("demo"), 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(layout.Dir("demo"), "audit.log")
	if _, err := PersistedAuditTail("demo"); !os.IsNotExist(err) {
		t.Fatalf("missing trail error = %v", err)
	}
	var data strings.Builder
	for i := range 300 {
		_, _ = fmt.Fprintf(&data, "event %d\n", i)
	}
	if err := os.WriteFile(path, []byte(data.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	lines, err := PersistedAuditTail("demo")
	if err != nil || len(lines) != 256 || lines[0] != "event 44" || lines[255] != "event 299" {
		t.Fatalf("bounded disk tail = %v, error %v", lines, err)
	}
	if _, err := PersistedAuditTail("../demo"); err == nil {
		t.Fatal("invalid name accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := PersistedAuditTail("demo"); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("non-regular trail accepted: %v", err)
	}
}
