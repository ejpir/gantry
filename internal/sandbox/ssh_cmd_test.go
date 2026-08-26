package sandbox

import (
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ejpir/gantry/internal/sandbox/layout"
)

func TestSSHHostUserUsesOpenSSHNamesForWindowsServiceSIDs(t *testing.T) {
	for _, test := range []struct {
		uid, username, want string
	}{
		{uid: "S-1-5-18", username: `WORKGROUP\MACHINE$`, want: "system"},
		{uid: "S-1-5-19", username: `NT AUTHORITY\LOCAL SERVICE`, want: "local service"},
		{uid: "1000", username: "alice", want: "alice"},
	} {
		if got := sshHostUser(&user.User{Uid: test.uid, Username: test.username}); got != test.want {
			t.Errorf("sshHostUser(%q, %q) = %q, want %q", test.uid, test.username, got, test.want)
		}
	}
}

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

func TestSSHInstallStateIsOutsideSandboxList(t *testing.T) {
	t.Setenv("GANTRY_HOME", filepath.Join(t.TempDir(), "sandboxes"))
	if filepath.Dir(sshInstallDir()) != filepath.Dir(layout.Root()) {
		t.Fatalf("ssh install dir %q is not sibling of sandbox root %q", sshInstallDir(), layout.Root())
	}
	if strings.HasPrefix(sshInstallDir(), layout.Root()+string(filepath.Separator)) {
		t.Fatalf("ssh install dir %q appears as a sandbox", sshInstallDir())
	}
}
