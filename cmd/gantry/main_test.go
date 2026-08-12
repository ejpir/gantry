package main

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ejpir/gantry/internal/sandbox"
	"github.com/ejpir/gantry/internal/secret"
)

func TestWriteMainHelpListsCommands(t *testing.T) {
	var output bytes.Buffer
	writeMainHelp(&output)
	got := output.String()
	for _, want := range []string{
		"gantry start <name>",
		"gantry exec <name>",
		"gantry tui",
		"gantry serve",
		"gantry image <verb>",
		"gantry share <verb>",
		"gantry ports <verb>",
		"gantry net-policy <verb>",
		"gantry import [<name>]",
		"gantry stop <name>",
		"gantry resume <name>",
		"gantry delete <name>",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("top-level help missing %q:\n%s", want, got)
		}
	}
}

func TestParseListenPorts(t *testing.T) {
	t.Parallel()

	ports, err := parseListenPorts("1026, 65535")
	if err != nil {
		t.Fatal(err)
	}
	if want := []uint32{1026, 65535}; !reflect.DeepEqual(ports, want) {
		t.Fatalf("ports = %v, want %v", ports, want)
	}

	for _, value := range []string{"", "0", "4294967296", "12x", "1,"} {
		t.Run(value, func(t *testing.T) {
			t.Parallel()
			if _, err := parseListenPorts(value); err == nil {
				t.Fatalf("parseListenPorts(%q) succeeded", value)
			}
		})
	}
}

func TestCommandHelpSucceeds(t *testing.T) {
	t.Parallel()
	if status := cmdRun([]string{"-h"}); status != 0 {
		t.Fatalf("cmdRun(-h) status = %d, want 0", status)
	}
	if status := runExec([]string{"-h"}); status != 0 {
		t.Fatalf("runExec(-h) status = %d, want 0", status)
	}
}

func TestOneShotExecPreservesRequiredIsolation(t *testing.T) {
	dir := t.TempDir()
	paths := make([]string, 3)
	for index, name := range []string{"kernel", "rootfs.erofs", "image.erofs"} {
		paths[index] = filepath.Join(dir, name)
		if err := os.WriteFile(paths[index], []byte("test"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	old := transientExec
	t.Cleanup(func() { transientExec = old })
	called := false
	transientExec = func(cfg sandbox.RunConfig, _ map[string]secret.Value, args []string, console bool) int {
		called = true
		if cfg.ProcessIsolation != "required" {
			t.Fatalf("process isolation = %q, want required", cfg.ProcessIsolation)
		}
		if console {
			t.Fatal("console unexpectedly enabled")
		}
		if !reflect.DeepEqual(args, []string{"/bin/true"}) {
			t.Fatalf("args = %q", args)
		}
		return 17
	}

	status := runExec([]string{
		"-kernel", paths[0],
		"-rootfs", paths[1],
		"-image", paths[2],
		"-rw=false",
		"-net=false",
		"-process-isolation=required",
		"--", "/bin/true",
	})
	if !called {
		t.Fatal("transient runner was not called")
	}
	if status != 17 {
		t.Fatalf("status = %d, want 17", status)
	}
}
