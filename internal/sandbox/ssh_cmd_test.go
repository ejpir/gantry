package sandbox

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ejpir/gantry/internal/sandbox/layout"
)

func TestUpdateManagedSSHBlockIdempotent(t *testing.T) {
	block := sshConfigBegin + "\nHost *.gantry\n" + sshConfigEnd
	first, err := updateManagedSSHBlock("Host example.com\n  User dev\n", block, false)
	if err != nil {
		t.Fatal(err)
	}
	second, err := updateManagedSSHBlock(first, block, false)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("managed update is not idempotent:\nfirst=%q\nsecond=%q", first, second)
	}
	if strings.Count(second, sshConfigBegin) != 1 || strings.Count(second, sshConfigEnd) != 1 {
		t.Fatalf("marker count in %q", second)
	}
	removed, err := updateManagedSSHBlock(second, block, true)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(removed, "gantry sandboxes") || !strings.Contains(removed, "Host example.com") {
		t.Fatalf("remove changed the wrong content: %q", removed)
	}
}

func TestUpdateManagedSSHBlockDetectsTamperingAndCRLF(t *testing.T) {
	block := sshConfigBegin + "\nHost *.gantry\n" + sshConfigEnd
	if _, err := updateManagedSSHBlock(sshConfigBegin+"\r\nHost *.gantry\r\n", block, false); err == nil {
		t.Fatal("missing end marker was accepted")
	}
	input := sshConfigBegin + "\r\nold\r\n" + sshConfigEnd + "\r\n"
	got, err := updateManagedSSHBlock(input, block, false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "\r") || !strings.Contains(got, "Host *.gantry") {
		t.Fatalf("CRLF update = %q", got)
	}
}

func TestParseIDESidecarArgs(t *testing.T) {
	for _, tc := range []struct {
		name     string
		argv     []string
		wantName string
		wantSize uint
		wantCmd  []string
		wantHelp bool
		wantErr  string
	}{
		{name: "interactive defaults", argv: []string{"dev"}, wantName: "dev"},
		{name: "size after name", argv: []string{"dev", "-disk-size", "8192"}, wantName: "dev", wantSize: 8192},
		{name: "size before name", argv: []string{"--disk-size=4096", "dev"}, wantName: "dev", wantSize: 4096},
		{name: "remote command", argv: []string{"dev", "-disk-size", "1024", "--", "df", "-h"}, wantName: "dev", wantSize: 1024, wantCmd: []string{"--", "df", "-h"}},
		{name: "help after name", argv: []string{"dev", "--help"}, wantHelp: true},
		{name: "size too small", argv: []string{"dev", "-disk-size", "128"}, wantErr: "between"},
		{name: "size malformed", argv: []string{"dev", "-disk-size=nope"}, wantErr: "invalid"},
		{name: "unknown option", argv: []string{"dev", "-other"}, wantErr: "unknown option"},
		{name: "command missing separator", argv: []string{"dev", "id"}, wantErr: "require --"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			name, options, command, help, err := parseIDESidecarArgs(tc.argv)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error = %v, want substring %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if name != tc.wantName || help != tc.wantHelp || strings.Join(command, "\x00") != strings.Join(tc.wantCmd, "\x00") {
				t.Fatalf("parsed name/help/command = %q/%v/%q, want %q/%v/%q", name, help, command, tc.wantName, tc.wantHelp, tc.wantCmd)
			}
			if tc.wantSize == 0 {
				if options.diskSizeMiB != nil {
					t.Fatalf("disk size = %d, want unset", *options.diskSizeMiB)
				}
			} else if options.diskSizeMiB == nil || *options.diskSizeMiB != tc.wantSize {
				t.Fatalf("disk size = %v, want %d", options.diskSizeMiB, tc.wantSize)
			}
		})
	}
}

func TestIDESidecarNameBudget(t *testing.T) {
	if got, err := ideSidecarName("demo"); err != nil || got != "demo-ide" {
		t.Fatalf("ideSidecarName = %q, %v", got, err)
	}
	if _, err := ideSidecarName(strings.Repeat("a", 61)); err == nil {
		t.Fatal("overlong derived sidecar name accepted")
	}
}

func TestIDESidecarPolicyPreservesPrimaryAndAddsEditorDomains(t *testing.T) {
	root := t.TempDir()
	t.Setenv("GANTRY_HOME", filepath.Join(root, "sandboxes"))
	primary := filepath.Join(root, "primary-policy.json")
	if err := os.WriteFile(primary, []byte(`{"default":"deny","rules":[{"action":"allow","proto":"tcp","ports":"443"}],"allowDomains":["example.com"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	path, err := ensureIDESidecarPolicy("demo-ide", primary)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var policy struct {
		Default      string           `json:"default"`
		Rules        []map[string]any `json:"rules"`
		AllowDomains []string         `json:"allowDomains"`
	}
	if err := json.Unmarshal(data, &policy); err != nil {
		t.Fatal(err)
	}
	if policy.Default != "deny" || len(policy.Rules) != 1 {
		t.Fatalf("primary policy was not preserved: %#v", policy)
	}
	joined := strings.Join(policy.AllowDomains, " ")
	for _, domain := range []string{"example.com", "code.visualstudio.com", "*.jetbrains.com"} {
		if !strings.Contains(joined, domain) {
			t.Errorf("sidecar policy missing %q: %v", domain, policy.AllowDomains)
		}
	}
}

func TestSSHInstallStateIsOutsideSandboxList(t *testing.T) {
	t.Setenv("GANTRY_HOME", filepath.Join(t.TempDir(), "sandboxes"))
	if filepath.Dir(sshInstallDir()) != filepath.Dir(layout.Root()) {
		t.Fatalf("ssh install dir %q is not sibling of sandbox root %q", sshInstallDir(), layout.Root())
	}
	if strings.HasPrefix(sshInstallDir(), layout.Root()+string(filepath.Separator)) {
		t.Fatalf("ssh install dir %q appears as a sandbox", sshInstallDir())
	}
}
