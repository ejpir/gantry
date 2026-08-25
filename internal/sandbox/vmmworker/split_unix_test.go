//go:build linux || darwin

package vmmworker

import (
	"os"
	"testing"
)

func TestResolveVhostShares(t *testing.T) {
	for _, test := range []struct {
		name, goos, goarch, value string
		want                      bool
		wantErr                   bool
	}{
		{name: "apple silicon default", goos: "darwin", goarch: "arm64", want: true},
		{name: "intel mac default", goos: "darwin", goarch: "amd64", want: false},
		{name: "linux default", goos: "linux", goarch: "arm64", want: false},
		{name: "explicit enable", goos: "linux", goarch: "arm64", value: "1", want: true},
		{name: "explicit disable", goos: "darwin", goarch: "arm64", value: "0", want: false},
		{name: "whitespace", goos: "darwin", goarch: "arm64", value: " 0 ", want: false},
		{name: "invalid", goos: "darwin", goarch: "arm64", value: "yes", wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := resolveVhostShares(test.goos, test.goarch, test.value)
			if (err != nil) != test.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, test.wantErr)
			}
			if got != test.want {
				t.Fatalf("enabled = %v, want %v", got, test.want)
			}
		})
	}
}

func TestSharedRAMBackingDir(t *testing.T) {
	if got := sharedRAMBackingDir("linux", "/sandbox/state"); got != "/sandbox/state" {
		t.Fatalf("Linux backing dir = %q", got)
	}
	if got := sharedRAMBackingDir("darwin", "/Users/me/.gantry"); got != os.TempDir() {
		t.Fatalf("Darwin backing dir = %q, want %q", got, os.TempDir())
	}
}
