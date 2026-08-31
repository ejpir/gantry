//go:build !windows

package sandbox

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestShellCommandContainsExpandedOpenSSHHost(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "command-substitution-ran")
	// OpenSSH performs this textual token expansion before invoking the user's
	// shell. If %h is not already quoted, the substitution creates marker.
	host := `x$(id>$GANTRY_SSH_INJECTION_MARKER).gantry`
	command := strings.Replace(shellCommand("printf", "%h"), "%h", host, 1)
	cmd := exec.Command("sh", "-c", command)
	cmd.Env = append(os.Environ(), "GANTRY_SSH_INJECTION_MARKER="+marker)
	output, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	if string(output) != host {
		t.Fatalf("expanded host argument = %q, want literal %q", output, host)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("OpenSSH host expansion was interpreted as shell syntax: %v", err)
	}
}
