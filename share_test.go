package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestParseShareSpec(t *testing.T) {
	for _, tc := range []struct {
		spec    string
		tag     string
		path    string
		ro      bool
		wantErr bool
	}{
		{spec: "hostshare=/Users/x", tag: "hostshare", path: "/Users/x"},
		{spec: "code=/Users/x/repos,ro", tag: "code", path: "/Users/x/repos", ro: true},
		{spec: "data=/a/b=c", tag: "data", path: "/a/b=c"}, // '=' allowed in path
		{spec: "bad", wantErr: true},
		{spec: "=/tmp", wantErr: true},
		{spec: "ok=", wantErr: true},
		{spec: "bad tag=/tmp", wantErr: true},
		{spec: "x=/tmp,ro,ro", path: "/tmp,ro", tag: "x", ro: true}, // only one suffix stripped
	} {
		t.Run(tc.spec, func(t *testing.T) {
			s, err := parseShareSpec(tc.spec, map[string]bool{})
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want error, got %+v", s)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if s.tag != tc.tag || s.path != tc.path || s.ro != tc.ro {
				t.Fatalf("got %+v, want tag=%q path=%q ro=%v", s, tc.tag, tc.path, tc.ro)
			}
		})
	}

	seen := map[string]bool{"dup": true}
	if _, err := parseShareSpec("dup=/tmp", seen); err == nil {
		t.Fatal("duplicate tag accepted")
	}
}

func TestShareManifestRoundTrip(t *testing.T) {
	shares := []hostShare{
		{tag: "hostshare", path: "/Users/x"},
		{tag: "code", path: "/Users/x/repos", ro: true},
	}
	path := filepath.Join(t.TempDir(), "sub", "shares.json")
	if err := writeShareManifest(path, shares); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m shareManifest
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if len(m.Shares) != 2 {
		t.Fatalf("manifest shares = %d, want 2", len(m.Shares))
	}
	// Multi-share layout: everything under /host/<tag>.
	if m.Shares[0].CtrPath != "/host/hostshare" || m.Shares[1].CtrPath != "/host/code" {
		t.Fatalf("container paths: %+v", m.Shares)
	}
	if m.Shares[0].VMPath != "/run/mnt/hostshare" || !m.Shares[1].RO {
		t.Fatalf("manifest entries: %+v", m.Shares)
	}

	// Single "hostshare" keeps the simple /host convention.
	if got := shareCtrPath("hostshare", false); got != "/host" {
		t.Fatalf("single-share ctr path = %q, want /host", got)
	}
}
