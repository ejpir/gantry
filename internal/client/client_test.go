package client

import (
	"encoding/json"
	"fmt"
	"github.com/ejpir/gantry/internal/image"
	"github.com/ejpir/gantry/internal/shares"
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
			cfg, err := ConfigJSON(tc.shares, false, []string{"/bin/sh"}, nil)
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

func TestConfigJSONShareHub(t *testing.T) {
	transport := &shares.Transport{Tag: shares.HubTag, VMPath: shares.HubVMPath}
	entries := []ShareEntry{
		{Tag: "code", RO: true, VMPath: shares.HubVMPath + "/code", CtrPath: "/host/code"},
		{Tag: "work", VMPath: shares.HubVMPath + "/work", CtrPath: "/workspace"},
	}
	cfg, err := ConfigJSONWithTransport(entries, transport, true, []string{"/bin/sh"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid([]byte(cfg)) {
		t.Fatalf("invalid JSON:\n%s", cfg)
	}
	for _, want := range []string{
		`"destination": "/run/gantry/shares", "type": "bind", "source": "/run/mnt/gantry-shares"`,
		`"destination": "/host", "type": "bind", "source": "/run/mnt/gantry-shares"`,
		`"destination": "/workspace", "type": "bind", "source": "/run/mnt/gantry-shares/work"`,
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(cfg, `"destination": "/host/code", "type": "bind"`) {
		t.Error("default /host/<tag> received a redundant bind")
	}
	if strings.Contains(cfg, `"destination": "/host", "type": "tmpfs"`) {
		t.Error("hub mode must not replace /host with a tmpfs")
	}

	// An explicit legacy /host alias covers the hub root; the internal stable
	// path remains available for all other live shares.
	entries[0].CtrPath = "/host"
	cfg, err = ConfigJSONWithTransport(entries, transport, true, []string{"/bin/sh"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cfg, `"destination": "/host", "type": "bind", "source": "/run/mnt/gantry-shares/code", "options": ["rbind","rprivate","ro"]`) {
		t.Errorf("missing explicit /host alias:\n%s", cfg)
	}
	if !strings.Contains(cfg, `"destination": "/run/gantry/shares"`) {
		t.Errorf("missing internal hub fallback:\n%s", cfg)
	}
}

func TestConfigJSONShareHubReadOnlyRoot(t *testing.T) {
	// rw=false: crun cannot create the hub bind targets inside a read-only
	// container root, so the hub must stay guest-side only.
	transport := &shares.Transport{Tag: shares.HubTag, VMPath: shares.HubVMPath}
	entries := []ShareEntry{
		{Tag: "code", RO: true, VMPath: shares.HubVMPath + "/code", CtrPath: "/host/code"},
	}
	cfg, err := ConfigJSONWithTransport(entries, transport, false, []string{"/bin/sh"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid([]byte(cfg)) {
		t.Fatalf("invalid JSON:\n%s", cfg)
	}
	for _, absent := range []string{"/run/gantry/shares", `"destination": "/host"`} {
		if strings.Contains(cfg, absent) {
			t.Errorf("read-only root must not carry hub bind %q", absent)
		}
	}
}

func TestConfigJSONTerminal(t *testing.T) {
	for _, tc := range []struct {
		terminal bool
		want     bool
	}{
		{terminal: true, want: true},
		{terminal: false, want: false},
	} {
		t.Run(fmt.Sprintf("terminal-%t", tc.terminal), func(t *testing.T) {
			cfg, err := configJSON(nil, false, []string{"/bin/sh"}, nil, tc.terminal)
			if err != nil {
				t.Fatal(err)
			}
			var v struct {
				Process struct {
					Terminal bool `json:"terminal"`
				} `json:"process"`
			}
			if err := json.Unmarshal([]byte(cfg), &v); err != nil {
				t.Fatal(err)
			}
			if v.Process.Terminal != tc.want {
				t.Errorf("terminal = %v, want %v", v.Process.Terminal, tc.want)
			}
		})
	}
}

func TestConfigJSONRWAndArgs(t *testing.T) {
	cfg, err := ConfigJSON(nil, true, []string{"/bin/bash", "-l"}, nil)
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

	// RW rootfs: erofs lower + ext4 upper + overlay.
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
	if got := LoadShares("/nonexistent-dir"); len(got) != 0 {
		t.Fatalf("LoadShares = %v, want none", got)
	}
}

// ConfigJSON must always emit valid JSON, with the image config driving
// user/env/cwd exactly per the precedence table (regression: the
// placeholder rewrite could have produced malformed config.json, which
// crun reports as the unhelpful "bad message").
func TestConfigJSONValidAndImageDriven(t *testing.T) {
	// nil image config: historical defaults
	cfg, err := ConfigJSON(nil, true, []string{"/bin/sh"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Process struct {
			User struct {
				UID, GID uint32
			} `json:"user"`
			Args []string `json:"args"`
			Env  []string `json:"env"`
			Cwd  string   `json:"cwd"`
		} `json:"process"`
	}
	if err := json.Unmarshal([]byte(cfg), &v); err != nil {
		t.Fatalf("invalid JSON (nil config): %v", err)
	}
	if v.Process.User.UID != 0 || v.Process.Cwd != "/" {
		t.Errorf("defaults: user=%d cwd=%q", v.Process.User.UID, v.Process.Cwd)
	}

	// full image config: image env wins, user/cwd from the image
	img := &image.Config{
		Env:        []string{"PATH=/custom/bin", "NGINX_ENTRYPOINT_QUIET_LOGS=1"},
		Entrypoint: []string{"/entry"},
		User:       "nginx",
		UID:        101, GID: 102,
		WorkingDir: "/app",
	}
	cfg, err = ConfigJSON(nil, false, img.Command(nil), img)
	if err != nil {
		t.Fatal(err)
	}
	v = struct {
		Process struct {
			User struct {
				UID, GID uint32
			} `json:"user"`
			Args []string `json:"args"`
			Env  []string `json:"env"`
			Cwd  string   `json:"cwd"`
		} `json:"process"`
	}{}
	if err := json.Unmarshal([]byte(cfg), &v); err != nil {
		t.Fatalf("invalid JSON (image config): %v", err)
	}
	if v.Process.User.UID != 101 || v.Process.User.GID != 102 {
		t.Errorf("user = %d:%d, want 101:102", v.Process.User.UID, v.Process.User.GID)
	}
	if v.Process.Cwd != "/app" {
		t.Errorf("cwd = %q, want /app", v.Process.Cwd)
	}
	if len(v.Process.Args) != 1 || v.Process.Args[0] != "/entry" {
		t.Errorf("args = %v, want [/entry]", v.Process.Args)
	}
	joined := strings.Join(v.Process.Env, " ")
	if !strings.Contains(joined, "PATH=/custom/bin") || strings.Contains(joined, "PATH=/usr/local/sbin") {
		t.Errorf("env must keep the image PATH only: %v", v.Process.Env)
	}
	if !strings.Contains(joined, "HOME=/") { // non-root user: HOME=/
		t.Errorf("env = %v", v.Process.Env)
	}
}

// One-shot command resolution: explicit -- CMD beats the image
// Entrypoint+Cmd, which beats the /bin/sh fallback. (Regression: Shell
// pre-defaulted Args to /bin/sh, so the image's entrypoint/cmd never
// applied to `gantry exec`.)
func TestResolveArgs(t *testing.T) {
	img := &image.Config{
		Entrypoint: []string{"/entry"},
		Cmd:        []string{"--serve"},
	}
	for _, tc := range []struct {
		name string
		args []string
		cfg  *image.Config
		want []string
	}{
		{"explicit args win", []string{"echo", "hi"}, img, []string{"echo", "hi"}},
		{"entrypoint+cmd", nil, img, []string{"/entry", "--serve"}},
		{"entrypoint only", nil, &image.Config{Entrypoint: []string{"/init"}}, []string{"/init"}},
		{"cmd only", nil, &image.Config{Cmd: []string{"ls"}}, []string{"ls"}},
		{"empty image config", nil, &image.Config{}, []string{"/bin/sh"}},
		{"nil image config", nil, nil, []string{"/bin/sh"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveArgs(tc.args, tc.cfg)
			if strings.Join(got, " ") != strings.Join(tc.want, " ") {
				t.Errorf("resolveArgs = %v, want %v", got, tc.want)
			}
		})
	}
}

// The one-shot session must carry the image config, secrets, and the
// exit-status sink through to Session, and must NOT pre-default Args
// (Session resolves image defaults; see TestResolveArgs).
func TestShellSessionOptions(t *testing.T) {
	img := &image.Config{Entrypoint: []string{"/entry"}, WorkingDir: "/app"}
	var status int
	opts := ShellOptions{
		StreamSock: "/tmp/stream.sock",
		RW:         true,
		ID:         "oneshot",
		ImgCfg:     img,
		Secrets:    []string{"TOKEN=abc"},
		ExitStatus: &status,
	}
	sess := opts.sessionOptions(nil)
	if sess.ImgCfg != img {
		t.Error("ImgCfg dropped")
	}
	if len(sess.Args) != 0 {
		t.Errorf("Args pre-defaulted to %v — image entrypoint would never apply", sess.Args)
	}
	if !sess.ExecIntoExisting {
		t.Error("one-shot sessions must use the Exec path (no secrets in the bundle)")
	}
	if sess.ExitStatus != &status {
		t.Error("ExitStatus sink dropped — `gantry exec -- false` would report success")
	}
	if len(sess.Secrets) != 1 || sess.Secrets[0] != "TOKEN=abc" {
		t.Errorf("Secrets = %v", sess.Secrets)
	}
	if sess.ID != "oneshot" || sess.StreamSock != "/tmp/stream.sock" || !sess.RW {
		t.Errorf("ID/StreamSock/RW not propagated: %+v", sess)
	}
}
