package workerconf

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
)

const landlockHelperEnv = "WORKERCONF_LANDLOCK_HELPER"

func TestPathLandlockDeniesNewPathsButKeepsDescriptors(t *testing.T) {
	if os.Getenv(landlockHelperEnv) == "deny" {
		path := os.Getenv("WORKERCONF_LANDLOCK_FILE")
		opened, err := os.Open(path)
		if err != nil {
			fmt.Fprintln(os.Stderr, "open positive control:", err)
			os.Exit(2)
		}
		defer func() { _ = opened.Close() }()
		abi, allowed, err := applyPathLandlock(nil)
		if err != nil {
			fmt.Fprintln(os.Stderr, "apply:", err)
			os.Exit(3)
		}
		if allowed != 0 {
			fmt.Fprintln(os.Stderr, "unexpected allowances:", allowed)
			os.Exit(4)
		}
		if _, err := os.Open(path); !landlockDenied(err) {
			fmt.Fprintln(os.Stderr, "new path open was not denied:", err)
			os.Exit(5)
		}
		buffer := make([]byte, 8)
		if _, err := opened.Read(buffer); err != nil || string(buffer) != "landlock" {
			fmt.Fprintln(os.Stderr, "inherited descriptor failed:", err, string(buffer))
			os.Exit(6)
		}
		fmt.Printf("LANDLOCK-DENY-OK ABI=%d\n", abi)
		os.Exit(0)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "input")
	if err := os.WriteFile(path, []byte("landlock"), 0o600); err != nil {
		t.Fatal(err)
	}
	output, err := runLandlockHelper(t, "deny", path, "")
	if unavailableLandlock(output) {
		t.Skipf("Landlock unavailable on test host: %s", output)
	}
	if err != nil {
		t.Fatalf("Landlock helper: %v\n%s", err, output)
	}
	if !strings.Contains(output, "LANDLOCK-DENY-OK") {
		t.Fatalf("Landlock helper output: %s", output)
	}
}

func TestPathLandlockAllowsOnlyDeclaredReadFile(t *testing.T) {
	if os.Getenv(landlockHelperEnv) == "allow" {
		allowedPath := os.Getenv("WORKERCONF_LANDLOCK_FILE")
		deniedPath := os.Getenv("WORKERCONF_LANDLOCK_DENIED_FILE")
		abi, allowed, err := applyPathLandlock([]string{allowedPath})
		if err != nil {
			fmt.Fprintln(os.Stderr, "apply:", err)
			os.Exit(2)
		}
		if allowed != 1 {
			fmt.Fprintln(os.Stderr, "allowance count:", allowed)
			os.Exit(3)
		}
		content, err := os.ReadFile(allowedPath)
		if err != nil || string(content) != "allowed" {
			fmt.Fprintln(os.Stderr, "allowed read failed:", err, string(content))
			os.Exit(4)
		}
		if _, err := os.Open(deniedPath); !landlockDenied(err) {
			fmt.Fprintln(os.Stderr, "sibling read was not denied:", err)
			os.Exit(5)
		}
		if err := os.WriteFile(allowedPath, []byte("changed"), 0o600); !landlockDenied(err) {
			fmt.Fprintln(os.Stderr, "allowed file write was not denied:", err)
			os.Exit(6)
		}
		fmt.Printf("LANDLOCK-ALLOW-OK ABI=%d\n", abi)
		os.Exit(0)
	}

	dir := t.TempDir()
	allowedPath := filepath.Join(dir, "allowed")
	deniedPath := filepath.Join(dir, "denied")
	if err := os.WriteFile(allowedPath, []byte("allowed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(deniedPath, []byte("denied"), 0o600); err != nil {
		t.Fatal(err)
	}
	output, err := runLandlockHelper(t, "allow", allowedPath, deniedPath)
	if unavailableLandlock(output) {
		t.Skipf("Landlock unavailable on test host: %s", output)
	}
	if err != nil {
		t.Fatalf("Landlock helper: %v\n%s", err, output)
	}
	if !strings.Contains(output, "LANDLOCK-ALLOW-OK") {
		t.Fatalf("Landlock helper output: %s", output)
	}
}

func TestPathLandlockRejectsBroadOrUncleanReadAllowances(t *testing.T) {
	for _, path := range []string{"relative", "/tmp/../etc/hosts", "/"} {
		path := path
		t.Run(strings.ReplaceAll(path, "/", "_"), func(t *testing.T) {
			if os.Getenv(landlockHelperEnv) == "invalid:"+path {
				_, _, err := applyPathLandlock([]string{path})
				if err == nil {
					os.Exit(2)
				}
				fmt.Fprintln(os.Stderr, "EXPECTED:", err)
				os.Exit(0)
			}
			output, err := runLandlockHelperMode(t, "invalid:"+path, "", "")
			if unavailableLandlock(output) {
				t.Skipf("Landlock unavailable on test host: %s", output)
			}
			if err != nil || !strings.Contains(output, "EXPECTED:") {
				t.Fatalf("invalid allowance helper: %v\n%s", err, output)
			}
		})
	}
}

func runLandlockHelper(t *testing.T, mode, allowedPath, deniedPath string) (string, error) {
	t.Helper()
	return runLandlockHelperMode(t, mode, allowedPath, deniedPath)
}

func runLandlockHelperMode(t *testing.T, mode, allowedPath, deniedPath string) (string, error) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^"+regexp.QuoteMeta(t.Name())+"$")
	cmd.Env = append(os.Environ(),
		landlockHelperEnv+"="+mode,
		"WORKERCONF_LANDLOCK_FILE="+allowedPath,
		"WORKERCONF_LANDLOCK_DENIED_FILE="+deniedPath,
	)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func landlockDenied(err error) bool {
	return errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM)
}

func unavailableLandlock(output string) bool {
	return strings.Contains(output, "query ABI: function not implemented") ||
		strings.Contains(output, "query ABI: operation not permitted")
}
