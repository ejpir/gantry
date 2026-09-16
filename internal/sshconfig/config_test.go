package sshconfig

import "testing"

func TestArgvCommandSurvivesOpenSSHDirectCommandParsing(t *testing.T) {
	got := ArgvCommand(`C:\Owner's Gantry\gantry.exe`, "ssh-known-hosts", `back\slash`, "%n")
	want := `'C:\\Owner\'s Gantry\\gantry.exe' ssh-known-hosts back\\slash %n`
	if got != want {
		t.Fatalf("ArgvCommand = %q, want %q", got, want)
	}
}
