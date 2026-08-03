package vmm

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"gantry/internal/shares"
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
			s, err := ParseShareSpec(tc.spec, map[string]bool{})
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want error, got %+v", s)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if s.Tag != tc.tag || s.Path != tc.path || s.RO != tc.ro {
				t.Fatalf("got %+v, want tag=%q path=%q ro=%v", s, tc.tag, tc.path, tc.ro)
			}
		})
	}

	seen := map[string]bool{"dup": true}
	if _, err := ParseShareSpec("dup=/tmp", seen); err == nil {
		t.Fatal("duplicate tag accepted")
	}
}

func TestShareManifestRoundTrip(t *testing.T) {
	shares := []Share{
		{Tag: "hostshare", Path: "/Users/x"},
		{Tag: "code", Path: "/Users/x/repos", RO: true},
	}
	path := filepath.Join(t.TempDir(), "sub", "shares.json")
	if err := WriteShareManifest(path, shares); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m ShareManifest
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

func TestParseShareSpecCtrPath(t *testing.T) {
	s, err := ParseShareSpec("piagent=/Users/x/.pi/agent@/root/.pi/agent", map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if s.CtrPath != "/root/.pi/agent" || s.Path != "/Users/x/.pi/agent" || s.RO {
		t.Fatalf("%+v", s)
	}
	s, err = ParseShareSpec("code=/Users/x/repos@/src,ro", map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if s.CtrPath != "/src" || !s.RO || s.Path != "/Users/x/repos" {
		t.Fatalf("%+v", s)
	}
	// relative container path rejected; bare path keeps the default
	if _, err := ParseShareSpec("x=/tmp@rel", map[string]bool{}); err == nil {
		t.Fatal("relative @CTRPATH accepted")
	}
	s, err = ParseShareSpec("x=/tmp", map[string]bool{})
	if err != nil || s.CtrPath != "" {
		t.Fatalf("default: %+v err=%v", s, err)
	}

	// explicit CtrPath flows into the manifest unchanged
	m := buildShareManifest([]Share{{Tag: "ws", Path: "/a"}, {Tag: "pia", Path: "/b", CtrPath: "/root/.pi/agent"}})
	if m.Shares[1].CtrPath != "/root/.pi/agent" {
		t.Fatalf("manifest CtrPath = %q", m.Shares[1].CtrPath)
	}
	if m.Shares[0].CtrPath != "/host/ws" {
		t.Fatalf("default CtrPath = %q", m.Shares[0].CtrPath)
	}
}

// Reserved directory entries must never become synthetic FUSE children.
func TestParseShareSpecRejectsReservedTags(t *testing.T) {
	for _, tag := range []string{".", ".."} {
		if _, err := ParseShareSpec(tag+"=/tmp", map[string]bool{}); err == nil {
			t.Errorf("tag %q accepted", tag)
		}
		if err := shares.ValidateShareTag(tag); err == nil {
			t.Errorf("ValidateShareTag(%q) accepted", tag)
		}
	}
	if _, err := ParseShareSpec("ok.tag=/tmp", map[string]bool{}); err != nil {
		t.Errorf("dotted tag rejected: %v", err)
	}
}
