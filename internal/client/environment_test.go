package client

import (
	"reflect"
	"slices"
	"testing"

	"github.com/ejpir/gantry/internal/image"
)

func TestProcessEnvironmentOverridesImageWithoutDuplicates(t *testing.T) {
	imageConfig := &image.Config{Env: []string{
		"PATH=/image/bin",
		"HTTP_PROXY=http://old.invalid:8080",
		"NO_PROXY=old.invalid",
	}}
	got := processEnvironment(imageConfig,
		[]string{"TOKEN=secret", "HTTP_PROXY=http://secret.invalid:8080"},
		[]string{"HTTP_PROXY=http://proxy.example:3128", "NO_PROXY=localhost"},
	)
	want := []string{
		"PATH=/image/bin",
		"HOME=/root",
		"TERM=xterm",
		"TOKEN=secret",
		"HTTP_PROXY=http://proxy.example:3128",
		"NO_PROXY=localhost",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("environment = %#v, want %#v", got, want)
	}
}

func TestConfigJSONIncludesEnvironmentOverrides(t *testing.T) {
	config, err := configJSONWithTransportCwdEnv(nil, nil, false, []string{"true"},
		&image.Config{Env: []string{"HTTPS_PROXY=http://old.invalid"}}, false, "",
		[]string{"HTTPS_PROXY=http://proxy.example:3128", "https_proxy=http://proxy.example:3128"})
	if err != nil {
		t.Fatal(err)
	}
	decoded := decodeRuntimeConfig(t, config)
	want := map[string]string{
		"HTTPS_PROXY": "http://proxy.example:3128",
		"https_proxy": "http://proxy.example:3128",
	}
	counts := make(map[string]int)
	for _, entry := range decoded.Process.Env {
		for name, value := range want {
			if entry == name+"="+value {
				counts[name]++
			}
		}
	}
	for name := range want {
		if counts[name] != 1 {
			t.Errorf("%s occurs %d times in %v", name, counts[name], decoded.Process.Env)
		}
	}
}

func TestSandboxContainerUsesTrustedUnprivilegedAnchor(t *testing.T) {
	config, err := sandboxContainerConfig(SessionOptions{ImgCfg: &image.Config{
		UID: 1001, GID: 1002, WorkingDir: "/work", Env: []string{"IMAGE_MARKER=present"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	decoded := decodeRuntimeConfig(t, config)
	if decoded.Process.User.UID != 65534 || decoded.Process.User.GID != 65534 {
		t.Fatalf("sandbox anchor user = %d:%d, want 65534:65534", decoded.Process.User.UID, decoded.Process.User.GID)
	}
	if decoded.Process.Cwd != "/" || !decoded.Process.NoNewPrivileges ||
		!reflect.DeepEqual(decoded.Process.Args, containerInitArgs) {
		t.Fatalf("sandbox init process = cwd %q args %v noNewPrivileges=%v",
			decoded.Process.Cwd, decoded.Process.Args, decoded.Process.NoNewPrivileges)
	}
	if capabilities := decoded.Process.Capabilities; capabilities != nil &&
		(len(capabilities.Bounding)+len(capabilities.Effective)+len(capabilities.Inheritable)+
			len(capabilities.Permitted)+len(capabilities.Ambient) != 0) {
		t.Fatalf("sandbox anchor retained capabilities: %+v", capabilities)
	}
	anchor := decoded.Mounts[len(decoded.Mounts)-1]
	if anchor.Destination != sandboxAnchorPath || anchor.Source != "/sbin/vminitd" || anchor.Type != "bind" {
		t.Fatalf("sandbox anchor mount = %+v", anchor)
	}
}

func TestIsolatedSessionConfigCarriesEphemeralSecretsAndToolsPath(t *testing.T) {
	base, err := configJSONWithTransportCwdEnv(nil, nil, true, []string{"true"},
		&image.Config{Env: []string{"PATH=/image/bin"}}, true, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := isolatedSessionConfig(base, SessionOptions{
		ImgCfg:      &image.Config{Env: []string{"PATH=/image/bin"}},
		Secrets:     []string{"TOKEN=secret"},
		Environment: []string{"HTTP_PROXY=http://proxy.invalid"},
		PathPrepend: []string{"/run/gantry/bin"},
	})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err = runtimeStdioPassthroughConfig(encoded)
	if err != nil {
		t.Fatal(err)
	}
	decoded := decodeRuntimeConfig(t, encoded)
	process := decoded.Process
	for _, want := range []string{
		"TOKEN=secret", "HTTP_PROXY=http://proxy.invalid", "PATH=/run/gantry/bin:/image/bin",
	} {
		if !slices.Contains(process.Env, want) {
			t.Errorf("session environment %v does not contain %q", process.Env, want)
		}
	}
	for _, mount := range decoded.Mounts {
		if mount.Destination == "/tmp" {
			t.Fatalf("isolated session replaces persistent sandbox /tmp: %+v", mount)
		}
	}
	if findMount(decoded.Mounts, "/proc") == nil {
		t.Fatal("isolated session lost namespace-specific /proc mount")
	}
	if decoded.Annotations[runtimeStdioPassthroughMarker] != "true" {
		t.Fatalf("runtime stdio marker = %q, want true", decoded.Annotations[runtimeStdioPassthroughMarker])
	}
}

func TestPrependPath(t *testing.T) {
	base := []string{"PATH=/usr/bin:/bin", "HOME=/root"}
	got := prependPath(base, []string{"/run/gantry/bin"})
	if got[0] != "PATH=/run/gantry/bin:/usr/bin:/bin" {
		t.Fatalf("prepend = %q", got[0])
	}
	if got[1] != "HOME=/root" || len(got) != 2 {
		t.Fatalf("other entries disturbed: %v", got)
	}
	// No PATH in the image: conventional tail so tools never stand alone.
	got = prependPath([]string{"HOME=/root"}, []string{"/run/gantry/bin"})
	if got[1] != "PATH=/run/gantry/bin:/usr/local/bin:/usr/bin:/bin" {
		t.Fatalf("missing-PATH prepend = %q", got[1])
	}
	// Empty prepend is a no-op on the same slice contents.
	if got := prependPath(base, nil); got[0] != "PATH=/usr/bin:/bin" {
		t.Fatalf("nil prepend changed PATH: %v", got)
	}
}
