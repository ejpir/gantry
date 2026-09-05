//go:build darwin

package sharefs

import (
	"os"
	"testing"
)

func TestDarwinDataVolumeScopeContainsFirmlinkDescendants(t *testing.T) {
	if _, err := os.Stat("/System/Volumes/Data"); err != nil {
		t.Skipf("APFS Data volume is unavailable: %v", err)
	}
	data, err := Identify("/System/Volumes/Data")
	if err != nil {
		t.Fatal(err)
	}
	users, err := Identify("/Users")
	if err != nil {
		t.Fatal(err)
	}
	system, err := Identify("/")
	if err != nil {
		t.Fatal(err)
	}
	if data.volume == system.volume {
		t.Fatal("sealed System and Data volumes received the same filesystem identity")
	}
	if !data.Contains(users) {
		t.Fatalf("Data identity scope %q does not contain /Users scope %q", data.scope, users.scope)
	}
	if users.Contains(data) {
		t.Fatalf("/Users scope %q unexpectedly contains Data scope %q", users.scope, data.scope)
	}
	if err := data.ValidateExport(); err == nil {
		t.Fatal("Data-volume root unexpectedly passed export validation")
	}
	volumes, err := Identify("/System/Volumes")
	if err != nil {
		t.Fatal(err)
	}
	if err := volumes.ValidateExport(); err == nil {
		t.Fatal("Data-volume namespace ancestor unexpectedly passed export validation")
	}
}
