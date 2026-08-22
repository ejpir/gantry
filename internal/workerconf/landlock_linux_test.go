package workerconf

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestMCPPathLandlockDeniesNewPathsButKeepsDescriptors(t *testing.T) {
	if os.Getenv("WORKERCONF_MCP_LANDLOCK_HELPER") == "1" {
		path := os.Getenv("WORKERCONF_MCP_LANDLOCK_FILE")
		opened, err := os.Open(path)
		if err != nil {
			fmt.Fprintln(os.Stderr, "open positive control:", err)
			os.Exit(2)
		}
		defer func() { _ = opened.Close() }()
		abi, err := applyMCPPathLandlock()
		if err != nil {
			fmt.Fprintln(os.Stderr, "apply:", err)
			os.Exit(3)
		}
		if _, err := os.Open(path); err == nil || (!errors.Is(err, syscall.EACCES) && !errors.Is(err, syscall.EPERM)) {
			fmt.Fprintln(os.Stderr, "new path open was not denied:", err)
			os.Exit(4)
		}
		buffer := make([]byte, 8)
		if _, err := opened.Read(buffer); err != nil || string(buffer) != "landlock" {
			fmt.Fprintln(os.Stderr, "inherited descriptor failed:", err, string(buffer))
			os.Exit(5)
		}
		fmt.Printf("LANDLOCK-OK ABI=%d\n", abi)
		os.Exit(0)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "input")
	if err := os.WriteFile(path, []byte("landlock"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestMCPPathLandlockDeniesNewPathsButKeepsDescriptors$")
	cmd.Env = append(os.Environ(),
		"WORKERCONF_MCP_LANDLOCK_HELPER=1",
		"WORKERCONF_MCP_LANDLOCK_FILE="+path,
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if strings.Contains(string(output), "apply: query ABI: function not implemented") ||
			strings.Contains(string(output), "apply: query ABI: operation not permitted") {
			t.Skipf("Landlock unavailable on test host: %s", output)
		}
		t.Fatalf("Landlock helper: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "LANDLOCK-OK") {
		t.Fatalf("Landlock helper output: %s", output)
	}
}
