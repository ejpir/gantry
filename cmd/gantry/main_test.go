package main

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/secret"
	"github.com/ejpir/gantry/internal/sharefs"
	"github.com/ejpir/gantry/internal/shares"
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
		"gantry export [options] <name>",
		"gantry stop <name>",
		"gantry resume <name>",
		"gantry delete <name>",
		"gantry version",
		"gantry update",
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

func TestPrepareRunFilesystemsRejectsVsockForwardOverlap(t *testing.T) {
	root := t.TempDir()
	forward := filepath.Join(root, "forward")
	if err := os.Mkdir(forward, 0o700); err != nil {
		t.Fatal(err)
	}
	identity, err := sharefs.Identify(forward)
	if err != nil {
		t.Fatal(err)
	}
	for _, readOnly := range []bool{false, true} {
		_, err := prepareRunFilesystems([]shares.Spec{{Tag: "host", Path: root, RO: readOnly}}, &identity)
		if err == nil || !strings.Contains(err.Error(), "overlaps vsock forwarding") {
			t.Fatalf("readOnly=%v overlap error = %v", readOnly, err)
		}
	}
}

func TestPrepareRunVsockForwardPinsSymlinkTarget(t *testing.T) {
	target := t.TempDir()
	link := filepath.Join(t.TempDir(), "forward")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	canonical, identity, err := prepareRunVsockForward(link)
	if err != nil {
		t.Fatal(err)
	}
	if canonical != identity.Path() || canonical == link {
		t.Fatalf("forward path was not pinned to symlink target: canonical=%q identity=%q link=%q", canonical, identity.Path(), link)
	}
}

func TestPrepareRunFilesystemsRejectsOverlappingShares(t *testing.T) {
	root := t.TempDir()
	child := filepath.Join(root, "child")
	if err := os.Mkdir(child, 0o700); err != nil {
		t.Fatal(err)
	}
	filesystems, err := prepareRunFilesystems([]shares.Spec{
		{Tag: "root", Path: root},
		{Tag: "child", Path: child},
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "overlaps share root") {
		t.Fatalf("overlap error = %v", err)
	}
	if len(filesystems) != 0 {
		t.Fatalf("failed preparation retained %d filesystems", len(filesystems))
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
	transientExec = func(cfg config.RunConfig, _ map[string]secret.Value, args []string, console bool) int {
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
