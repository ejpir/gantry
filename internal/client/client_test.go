package client

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestConfigJSONShare(t *testing.T) {
	for _, tc := range []struct {
		name    string
		shares  []ShareEntry
		want    []string
		notWant []string
	}{
		{name: "none", notWant: []string{`"destination": "/host"`}},
		{
			name: "single rw hostshare",
			shares: []ShareEntry{
				{Tag: "hostshare", VMPath: "/run/mnt/hostshare", CtrPath: "/host"},
			},
			want:    []string{`"destination": "/host"`, `"source": "/run/mnt/hostshare"`},
			notWant: []string{`"type": "tmpfs", "source": "tmpfs", "options": ["nosuid","nodev","rw"]`},
		},
		{
			name: "multi with ro",
			shares: []ShareEntry{
				{Tag: "hostshare", VMPath: "/run/mnt/hostshare", CtrPath: "/host/hostshare"},
				{Tag: "code", RO: true, VMPath: "/run/mnt/code", CtrPath: "/host/code"},
			},
			want: []string{
				`"destination": "/host", "type": "tmpfs"`,
				`"destination": "/host/hostshare"`,
				`"destination": "/host/code", "type": "bind", "source": "/run/mnt/code", "options": ["rbind","rprivate","ro"]`,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := ConfigJSON(tc.shares, false, []string{"/bin/sh"})
			if err != nil {
				t.Fatal(err)
			}
			if !json.Valid([]byte(cfg)) {
				t.Fatalf("invalid JSON:\n%s", cfg)
			}
			for _, w := range tc.want {
				if !strings.Contains(cfg, w) {
					t.Errorf("missing %q", w)
				}
			}
			for _, nw := range tc.notWant {
				if strings.Contains(cfg, nw) {
					t.Errorf("unexpected %q", nw)
				}
			}
		})
	}
}

func TestConfigJSONRWAndArgs(t *testing.T) {
	cfg, err := ConfigJSON(nil, true, []string{"/bin/bash", "-l"})
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid([]byte(cfg)) {
		t.Fatalf("invalid JSON:\n%s", cfg)
	}
	for _, want := range []string{
		`"args": ["/bin/bash","-l"]`,
		`"root": {"path": "rootfs", "readonly": false}`,
		`"HOME=/root"`,
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("missing %q", want)
		}
	}

	// RW rootfs: erofs lower + ext4 upper + overlay, sbx rwlayer style.
	mounts := RootfsMounts(true)
	if len(mounts) != 3 {
		t.Fatalf("rw rootfs mounts = %d, want 3", len(mounts))
	}
	if mounts[0].Type != "erofs" || mounts[0].Source != "/dev/vdb" {
		t.Fatalf("lower: %+v", mounts[0])
	}
	if mounts[1].Type != "ext4" || mounts[1].Source != "/dev/vdc" {
		t.Fatalf("upper layer: %+v", mounts[1])
	}
	ov := mounts[2]
	if ov.Type != "format/overlay" {
		t.Fatalf("overlay mount: %+v", ov)
	}
	joined := strings.Join(ov.Options, " ")
	for _, want := range []string{"lowerdir={{mount 0}}", "upperdir={{mount 1}}/upper", "workdir={{mount 1}}/work"} {
		if !strings.Contains(joined, want) {
			t.Errorf("overlay options missing %q", want)
		}
	}

	if ro := RootfsMounts(false); len(ro) != 1 || ro[0].Type != "erofs" {
		t.Fatalf("ro rootfs mounts: %+v", ro)
	}
}

func TestLoadSharesMissing(t *testing.T) {
	if got := LoadShares("/nonexistent-dir/1025.sock"); len(got) != 0 {
		t.Fatalf("LoadShares = %v, want none", got)
	}
}
