package config

import (
	"flag"
	"testing"
)

func TestRunOptionsPreserveExplicitDefaultsAndDetachSlices(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	flags := RegisterRunFlags(fs)
	if err := fs.Parse([]string{"-rw=false", "-mem=512", "-cpus=1", "-disk-size=512", "-share", "code=/tmp/code"}); err != nil {
		t.Fatal(err)
	}
	options := flags.Options(fs)
	if !options.Explicit.RW || options.RW || !options.Explicit.Memory || !options.Explicit.CPUs || !options.Explicit.DiskSize {
		t.Fatalf("explicit defaults lost: %+v", options)
	}
	options.Shares[0] = "other=/tmp/other"
	if flags.Shares.List()[0] != "code=/tmp/code" {
		t.Fatal("typed request aliases CLI storage")
	}
}
