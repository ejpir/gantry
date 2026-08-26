//go:build windows

package mcpworker

import (
	"strings"
	"testing"
)

func TestWindowsMCPWorkerEnvironmentHasNoAmbientAuthority(t *testing.T) {
	t.Setenv("TEMP", `C:\Users\tester\AppData\Local\Temp`)
	t.Setenv("TMP", `C:\Users\tester\AppData\Local\Temp`)
	for _, entry := range workerEnvironment() {
		name, _, _ := strings.Cut(entry, "=")
		switch name {
		case "SystemRoot", "WINDIR", "SystemDrive":
		default:
			t.Fatalf("unexpected MCP worker environment entry %q", entry)
		}
		upper := strings.ToUpper(entry)
		for _, forbidden := range []string{"TOKEN", "SECRET", "PASSWORD", "PROXY", "GANTRY_HOME", "HOME="} {
			if strings.Contains(upper, forbidden) {
				t.Fatalf("MCP worker environment carries %q: %q", forbidden, entry)
			}
		}
	}
}
