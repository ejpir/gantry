//go:build darwin

package workerconf

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestApplyDenyAllProfilesDarwin applies the production VMM and MCP Seatbelt
// profiles in disposable children. It complements the role-specific network
// test: deny-all workers must retain inherited descriptor I/O while proving
// that new filesystem, network, executable, and process-enumeration authority
// is unavailable. The complete supervisor-to-worker path is exercised by the
// local macOS functional battery.
func TestApplyDenyAllProfilesDarwin(t *testing.T) {
	if profile := os.Getenv("WORKERCONF_DENY_DARWIN_HELPER"); profile != "" {
		denyConfinedDarwinHelper(profile)
		return
	}

	for _, profile := range []string{"vmm", "mcp"} {
		t.Run(profile, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestApplyDenyAllProfilesDarwin$", "-test.v")
			cmd.Env = append(os.Environ(), "WORKERCONF_DENY_DARWIN_HELPER="+profile)
			output, err := cmd.CombinedOutput()
			text := string(output)
			if err != nil {
				t.Fatalf("darwin %s confinement helper: %v\n%s", profile, err, text)
			}
			if !strings.Contains(text, "INHERITED-PIPE-OK") {
				t.Fatalf("%s helper lost inherited descriptor I/O:\n%s", profile, text)
			}

			var report Report
			for _, line := range strings.Split(text, "\n") {
				if strings.HasPrefix(line, "{\"platform\"") {
					if err := json.Unmarshal([]byte(line), &report); err != nil {
						t.Fatalf("decode %s confinement report: %v\n%s", profile, err, text)
					}
				}
			}
			if report.Platform != "darwin" || !report.Applied {
				t.Fatalf("%s confinement was not applied: %+v\n%s", profile, report, text)
			}
			for _, property := range []string{PropFSRead, PropFSWrite, PropNetDial, PropExec, PropProcEnum} {
				if got := report.Property(property); got.State != StateEnforced {
					t.Errorf("%s %s = %s (%s), want enforced\n%s", profile, property, got.State, got.Detail, text)
				}
			}
			if got := report.Property(PropProcSignal); got.State != StateEnforced && got.State != StateIndeterminate {
				t.Errorf("%s %s = %s (%s), want enforced or honestly indeterminate\n%s",
					profile, PropProcSignal, got.State, got.Detail, text)
			}
		})
	}
}

func denyConfinedDarwinHelper(profile string) {
	reader, writer, err := os.Pipe()
	if err != nil {
		denyDarwinHelperFatal("create inherited pipe", err)
	}
	defer func() {
		_ = reader.Close()
		_ = writer.Close()
	}()

	var spec Spec
	switch profile {
	case "vmm":
		spec = DefaultSpec(4, "")
	case "mcp":
		spec = MCPSpec(4, "")
	default:
		denyDarwinHelperFatal("unknown profile "+profile, nil)
	}
	report, err := Apply(spec)
	if err != nil {
		denyDarwinHelperFatal("apply "+profile+" Seatbelt", err)
	}
	if _, err := writer.Write([]byte{'x'}); err != nil {
		denyDarwinHelperFatal("write inherited pipe", err)
	}
	var value [1]byte
	if _, err := reader.Read(value[:]); err != nil || value[0] != 'x' {
		denyDarwinHelperFatal("read inherited pipe", err)
	}
	fmt.Println("INHERITED-PIPE-OK")

	Verify(spec, report)
	data, err := json.Marshal(report)
	if err != nil {
		denyDarwinHelperFatal("encode confinement report", err)
	}
	_, _ = os.Stdout.Write(append(data, '\n'))
}

func denyDarwinHelperFatal(operation string, err error) {
	_, _ = fmt.Fprintln(os.Stderr, operation+":", err)
	os.Exit(2)
}
