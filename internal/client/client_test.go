package client

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ejpir/gantry/internal/image"
	"github.com/ejpir/gantry/internal/shares"

	"github.com/opencontainers/runtime-spec/specs-go"
)

func decodeRuntimeConfig(t *testing.T, encoded string) runtimeConfig {
	t.Helper()
	var config runtimeConfig
	if err := json.Unmarshal([]byte(encoded), &config); err != nil {
		t.Fatalf("invalid runtime config: %v\n%s", err, encoded)
	}
	return config
}

func findMount(mounts []specs.Mount, destination string) *specs.Mount {
	for i := range mounts {
		if mounts[i].Destination == destination {
			return &mounts[i]
		}
	}
	return nil
}

func hasOption(mount *specs.Mount, option string) bool {
	if mount == nil {
		return false
	}
	for _, candidate := range mount.Options {
		if candidate == option {
			return true
		}
	}
	return false
}

func TestConfigJSONShare(t *testing.T) {
	encoded, err := ConfigJSON(nil, false, []string{"/bin/sh"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if mount := findMount(decodeRuntimeConfig(t, encoded).Mounts, "/host"); mount != nil {
		t.Fatalf("shareless config has /host mount: %+v", mount)
	}

	encoded, err = ConfigJSON([]ShareEntry{{Tag: "hostshare", VMPath: "/run/mnt/hostshare", CtrPath: "/host"}}, false, []string{"/bin/sh"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	mount := findMount(decodeRuntimeConfig(t, encoded).Mounts, "/host")
	if mount == nil || mount.Type != "bind" || mount.Source != "/run/mnt/hostshare" {
		t.Fatalf("single host share mount = %+v", mount)
	}

	entries := []ShareEntry{
		{Tag: "hostshare", VMPath: "/run/mnt/hostshare", CtrPath: "/host/hostshare"},
		{Tag: "code", RO: true, VMPath: "/run/mnt/code", CtrPath: "/host/code"},
	}
	encoded, err = ConfigJSON(entries, false, []string{"/bin/sh"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	mounts := decodeRuntimeConfig(t, encoded).Mounts
	if mount := findMount(mounts, "/host"); mount == nil || mount.Type != "tmpfs" {
		t.Fatalf("multi-share /host mount = %+v", mount)
	}
	if mount := findMount(mounts, "/host/hostshare"); mount == nil || mount.Source != "/run/mnt/hostshare" {
		t.Fatalf("hostshare mount = %+v", mount)
	}
	if mount := findMount(mounts, "/host/code"); mount == nil || mount.Source != "/run/mnt/code" || !hasOption(mount, "ro") {
		t.Fatalf("read-only code mount = %+v", mount)
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
	mounts := decodeRuntimeConfig(t, cfg).Mounts
	for destination, source := range map[string]string{
		"/run/gantry/shares": "/run/mnt/gantry-shares",
		"/host":              "/run/mnt/gantry-shares",
		"/workspace":         "/run/mnt/gantry-shares/work",
	} {
		if mount := findMount(mounts, destination); mount == nil || mount.Source != source {
			t.Errorf("mount %s = %+v, want source %s", destination, mount, source)
		}
	}
	if findMount(mounts, "/host/code") != nil {
		t.Error("default /host/<tag> received a redundant bind")
	}
	if mount := findMount(mounts, "/host"); mount != nil && mount.Type == "tmpfs" {
		t.Error("hub mode must not replace /host with a tmpfs")
	}

	// An explicit legacy /host alias covers the hub root; the internal stable
	// path remains available for all other live shares.
	entries[0].CtrPath = "/host"
	cfg, err = ConfigJSONWithTransport(entries, transport, true, []string{"/bin/sh"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	mounts = decodeRuntimeConfig(t, cfg).Mounts
	if mount := findMount(mounts, "/host"); mount == nil || mount.Source != "/run/mnt/gantry-shares/code" || !hasOption(mount, "ro") {
		t.Errorf("explicit /host alias = %+v", mount)
	}
	if findMount(mounts, "/run/gantry/shares") == nil {
		t.Error("missing internal hub fallback")
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
	mounts := decodeRuntimeConfig(t, cfg).Mounts
	for _, destination := range []string{"/run/gantry/shares", "/host"} {
		if mount := findMount(mounts, destination); mount != nil {
			t.Errorf("read-only root carries hub mount %+v", mount)
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
	config := decodeRuntimeConfig(t, cfg)
	if strings.Join(config.Process.Args, " ") != "/bin/bash -l" {
		t.Errorf("args = %v", config.Process.Args)
	}
	if config.Root.Path != "rootfs" || config.Root.Readonly {
		t.Errorf("root = %+v", config.Root)
	}
	if !strings.Contains(strings.Join(config.Process.Env, " "), "HOME=/root") {
		t.Errorf("env = %v", config.Process.Env)
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

func TestLoadShareManifestSupportsLiveTransportShapes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "shares.json")
	perDevice := `{"shares":[{"tag":"code","vmPath":"/run/mnt/code","ctrPath":"/host/code"}]}`
	if err := os.WriteFile(path, []byte(perDevice), 0o600); err != nil {
		t.Fatal(err)
	}
	manifest := LoadShareManifest(dir)
	if manifest.Version != 0 || manifest.Transport != nil || len(manifest.Shares) != 1 {
		t.Fatalf("per-device manifest = %+v", manifest)
	}

	hub := `{"version":2,"generation":7,"transport":{"tag":"gantry-shares","vmPath":"/run/mnt/gantry-shares"},"shares":[]}`
	if err := os.WriteFile(path, []byte(hub), 0o600); err != nil {
		t.Fatal(err)
	}
	manifest = LoadShareManifest(dir)
	if manifest.Version != shares.ManifestVersion || manifest.Generation != 7 || manifest.Transport == nil || manifest.Transport.Tag != shares.HubTag {
		t.Fatalf("hub manifest = %+v", manifest)
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

func BenchmarkConfigJSONWithTransport(b *testing.B) {
	transport := &shares.Transport{Tag: shares.HubTag, VMPath: shares.HubVMPath}
	entries := []ShareEntry{
		{Tag: "code", RO: true, VMPath: shares.HubVMPath + "/code", CtrPath: "/host/code"},
		{Tag: "work", VMPath: shares.HubVMPath + "/work", CtrPath: "/workspace"},
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := ConfigJSONWithTransport(entries, transport, true, []string{"/bin/sh"}, nil); err != nil {
			b.Fatal(err)
		}
	}
}
