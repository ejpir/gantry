package shares

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseSpec(t *testing.T) {
	for _, tc := range []struct {
		spec    string
		tag     string
		path    string
		ro      bool
		wantErr bool
	}{
		{spec: "hostshare=/Users/x", tag: "hostshare", path: "/Users/x"},
		{spec: "code=/Users/x/repos,ro", tag: "code", path: "/Users/x/repos", ro: true},
		{spec: "data=/a/b=c", tag: "data", path: "/a/b=c"},
		{spec: "bad", wantErr: true},
		{spec: "=/tmp", wantErr: true},
		{spec: "ok=", wantErr: true},
		{spec: "bad tag=/tmp", wantErr: true},
		{spec: "x=/tmp,ro,ro", wantErr: true},
	} {
		t.Run(tc.spec, func(t *testing.T) {
			got, err := ParseSpec(tc.spec)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want error, got %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.Tag != tc.tag || got.Path != tc.path || got.RO != tc.ro {
				t.Fatalf("got %+v, want tag=%q path=%q ro=%v", got, tc.tag, tc.path, tc.ro)
			}
		})
	}
}

func TestParseSpecsRejectsDuplicateTags(t *testing.T) {
	got, err := ParseSpecs([]string{"code=/src", "data=/var/lib/data,ro"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Tag != "code" || got[1].Tag != "data" || !got[1].RO {
		t.Fatalf("ParseSpecs() = %+v", got)
	}

	if _, err := ParseSpecs([]string{"dup=/one", "dup=/two"}); err == nil {
		t.Fatal("duplicate tag accepted")
	} else if !strings.Contains(err.Error(), "dup=/one") || !strings.Contains(err.Error(), "dup=/two") {
		t.Fatalf("duplicate error lacks conflicting specs: %v", err)
	}

	if _, err := ParseSpecs([]string{"ok=/one", "invalid"}); err == nil {
		t.Fatal("invalid spec accepted")
	} else if !strings.Contains(err.Error(), `share "invalid"`) {
		t.Fatalf("parse error lacks the invalid spec: %v", err)
	}
}

func TestSpecStringRoundTrip(t *testing.T) {
	original, err := ParseSpec("workspace=/Users/x@/workspace,ro,uid=1000,gid=1000")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := original.String(), "workspace=/Users/x@/workspace,ro,uid=1000,gid=1000"; got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
	roundTrip, err := ParseSpec(original.String())
	if err != nil {
		t.Fatal(err)
	}
	if roundTrip.Tag != original.Tag || roundTrip.Path != original.Path || roundTrip.CtrPath != original.CtrPath ||
		roundTrip.RO != original.RO || roundTrip.UID == nil || roundTrip.GID == nil ||
		*roundTrip.UID != *original.UID || *roundTrip.GID != *original.GID {
		t.Fatalf("round trip = %+v, want %+v", roundTrip, original)
	}
}

func TestSpecStringEncodesGrammarDelimiters(t *testing.T) {
	for _, original := range []Spec{
		{Tag: "host-at", Path: "/tmp/name@host"},
		{Tag: "option-suffix", Path: "/tmp/data,ro"},
		{Tag: "target-at", Path: "/tmp/data", CtrPath: "/workspace/name@host", RO: true},
	} {
		t.Run(original.Tag, func(t *testing.T) {
			encoded := original.String()
			if !strings.HasSuffix(encoded, ",encoding=base64url") {
				t.Fatalf("String() = %q, want encoded fallback", encoded)
			}
			roundTrip, err := ParseSpec(encoded)
			if err != nil {
				t.Fatal(err)
			}
			if !equalSpec(roundTrip, original) {
				t.Fatalf("round trip = %+v, want %+v", roundTrip, original)
			}
		})
	}
}

func TestParseSpecEncodedPathValidation(t *testing.T) {
	for _, value := range []string{
		"bad=%%%,encoding=base64url",
		"bad=L3RtcA@cmVsYXRpdmU,encoding=base64url",
		"bad=L3RtcA,encoding=base64url,encoding=base64url",
	} {
		if _, err := ParseSpec(value); err == nil {
			t.Errorf("ParseSpec(%q) accepted malformed encoding", value)
		}
	}
}

func TestManifestRoundTrip(t *testing.T) {
	specs := []Spec{
		{Tag: "hostshare", Path: "/Users/x"},
		{Tag: "code", Path: "/Users/x/repos", RO: true},
	}
	path := filepath.Join(t.TempDir(), "sub", "shares.json")
	if err := WriteManifest(path, specs); err != nil {
		t.Fatal(err)
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var manifest Manifest
	if err := json.Unmarshal(payload, &manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest.Shares) != 2 {
		t.Fatalf("manifest shares = %d, want 2", len(manifest.Shares))
	}
	if manifest.Shares[0].CtrPath != "/host/hostshare" || manifest.Shares[1].CtrPath != "/host/code" {
		t.Fatalf("container paths: %+v", manifest.Shares)
	}
	if manifest.Shares[0].VMPath != "/run/mnt/hostshare" || !manifest.Shares[1].RO {
		t.Fatalf("manifest entries: %+v", manifest.Shares)
	}
	if got := defaultPerDeviceContainerPath("hostshare", false); got != "/host" {
		t.Fatalf("single-share container path = %q, want /host", got)
	}
}

func TestParseSpecContainerPath(t *testing.T) {
	spec, err := ParseSpec("piagent=/Users/x/.pi/agent@/root/.pi/agent")
	if err != nil {
		t.Fatal(err)
	}
	if spec.CtrPath != "/root/.pi/agent" || spec.Path != "/Users/x/.pi/agent" || spec.RO {
		t.Fatalf("%+v", spec)
	}
	spec, err = ParseSpec("code=/Users/x/repos@/src,ro")
	if err != nil {
		t.Fatal(err)
	}
	if spec.CtrPath != "/src" || !spec.RO || spec.Path != "/Users/x/repos" {
		t.Fatalf("%+v", spec)
	}
	spec, err = ParseSpec("code=/Users/name@host@/src")
	if err != nil {
		t.Fatal(err)
	}
	if spec.Path != "/Users/name@host" || spec.CtrPath != "/src" {
		t.Fatalf("last @ must remain the container delimiter: %+v", spec)
	}
	if got := spec.String(); got != "code=/Users/name@host@/src" {
		t.Fatalf("representable @ path encoded unnecessarily: %q", got)
	}
	if _, err := ParseSpec("x=/tmp@rel"); err == nil {
		t.Fatal("relative @CTRPATH accepted")
	}
	spec, err = ParseSpec("x=/tmp")
	if err != nil || spec.CtrPath != "" {
		t.Fatalf("default: %+v err=%v", spec, err)
	}

	manifest := BuildManifest([]Spec{{Tag: "ws", Path: "/a"}, {Tag: "pia", Path: "/b", CtrPath: "/root/.pi/agent"}})
	if manifest.Shares[1].CtrPath != "/root/.pi/agent" {
		t.Fatalf("manifest CtrPath = %q", manifest.Shares[1].CtrPath)
	}
	if manifest.Shares[0].CtrPath != "/host/ws" {
		t.Fatalf("default CtrPath = %q", manifest.Shares[0].CtrPath)
	}
}

func TestParseSpecGuestOwnership(t *testing.T) {
	spec, err := ParseSpec("workspace=/Users/x@/workspace,ro,uid=1000,gid=1000")
	if err != nil {
		t.Fatal(err)
	}
	if spec.UID == nil || spec.GID == nil || *spec.UID != 1000 || *spec.GID != 1000 || !spec.RO {
		t.Fatalf("ownership mapping = uid=%v gid=%v ro=%v", spec.UID, spec.GID, spec.RO)
	}
	if _, err := ParseSpec("bad=/tmp,uid=1000"); err == nil {
		t.Fatal("uid without gid was accepted")
	}
	if _, err := ParseSpec("bad=/tmp,uid=agent,gid=1000"); err == nil {
		t.Fatal("non-numeric uid was accepted")
	}
}

func TestParseSpecRejectsReservedTags(t *testing.T) {
	for _, tag := range []string{".", ".."} {
		if _, err := ParseSpec(tag + "=/tmp"); err == nil {
			t.Errorf("tag %q accepted", tag)
		}
		if err := ValidateShareTag(tag); err == nil {
			t.Errorf("ValidateShareTag(%q) accepted", tag)
		}
	}
	if _, err := ParseSpec("ok.tag=/tmp"); err != nil {
		t.Errorf("dotted tag rejected: %v", err)
	}
}

func TestParseSpecUnknownOption(t *testing.T) {
	if _, err := ParseSpec("code=/tmp/x,uidx=1000"); err == nil {
		t.Fatal("want unknown-option error for ,uidx=1000")
	}
	if _, err := ParseSpec("code=/tmp/x,rw"); err != nil {
		t.Fatalf("plain comma path segment must keep parsing: %v", err)
	}
	_, err := ParseSpec("code=/tmp/x,uid=abc,gid=1")
	if err == nil || !strings.Contains(err.Error(), "invalid syntax") {
		t.Fatalf("uid error should carry the strconv reason, got %v", err)
	}
}
