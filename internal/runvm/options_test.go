package runvm

import (
	"flag"
	"reflect"
	"strings"
	"testing"
)

func TestRunFlagsRoundTripWithoutOpeningHostFiles(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	r := BindFlags(fs)
	args := []string{"-kernel", "/only/on/manager/kernel", "-initrd", "/remote/initrd", "-rootfs", "/remote/root with spaces", "-disk", "/remote/disk", "-share", "code=/remote/code,ro", "-net", "/remote/network.sock", "-net-vfkit=false", "-net-dhcp=false", "-vsockfwd", "/remote/vsock", "-vsocklisten=", "-guestcid", "42", "-mem", "1024", "-cpus", "2", "-append", "console=ttyS0 literal=$HOME;false"}
	if err := fs.Parse(args); err != nil {
		t.Fatal(err)
	}
	if err := Validate(*r); err != nil {
		t.Fatal(err)
	}
	wireArgs := Args(*r)
	if !reflect.DeepEqual(wireArgs[:2], []string{"run", "-remote="}) {
		t.Fatal("helper can inherit a remote default")
	}
	copyFS := flag.NewFlagSet("copy", flag.ContinueOnError)
	copied := BindFlags(copyFS)
	if err := copyFS.Parse(wireArgs[2:]); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r, copied) {
		t.Fatalf("flags changed across remote hop: %+v / %+v", r, copied)
	}
	if copied.VsockListen == nil || *copied.VsockListen != "" || *copied.NetworkDHCP || *copied.NetworkVFKIT {
		t.Fatal("explicit empty/false lost")
	}
}

func TestRunRequestRejectsInvalidOrUnboundedWork(t *testing.T) {
	for _, args := range [][]string{
		{}, {"-kernel", "/k"}, {"-rootfs", "/r"}, {"-kernel", "/k", "-rootfs", "/r", "-mem", "0"},
		{"-kernel", "/k", "-rootfs", "/r", "-cpus", "0"}, {"-kernel", "a\x00b", "-rootfs", "/r"},
		{"-kernel", "/k", "-rootfs", "/r", "-net", "/socket", "-net-mac", "bad"},
		{"-kernel", "/k", "-rootfs", "/r", "-vsockfwd", "/f", "-vsocklisten", "4294967296"},
	} {
		fs := flag.NewFlagSet("bad", flag.ContinueOnError)
		r := BindFlags(fs)
		if err := fs.Parse(args); err != nil {
			t.Fatal(err)
		}
		if err := Validate(*r); err == nil {
			t.Fatalf("accepted invalid raw run %v", args)
		}
	}
	r := Defaults()
	r.Kernel, r.Rootfs = "/k", "/r"
	r.Stdin = strings.Repeat("x", MaxStdinBytes+1)
	if Validate(r) == nil {
		t.Fatal("oversized stdin accepted")
	}
	r.Stdin = ""
	r.MaxOutputBytes = MaxOutputBytes + 1
	if Validate(r) == nil {
		t.Fatal("unbounded console accepted")
	}
	r.MaxOutputBytes = 1
	r.TimeoutSeconds = MaxTimeoutSeconds + 1
	if Validate(r) == nil {
		t.Fatal("unbounded runtime accepted")
	}
}
