//go:build linux

package sharefs

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestLinuxIdentityDetectsBindMountedAncestor(t *testing.T) {
	root := t.TempDir()
	realParent := filepath.Join(root, "real")
	state := filepath.Join(realParent, "sandbox")
	alias := filepath.Join(root, "alias")
	stateChild := filepath.Join(state, "child")
	childAlias := filepath.Join(root, "child-alias")
	for _, directory := range []string{stateChild, alias, childAlias} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := unix.Mount(realParent, alias, "", unix.MS_BIND, ""); err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skip("bind mounts require CAP_SYS_ADMIN")
		}
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Unmount(alias, unix.MNT_DETACH) })

	stateIdentity, err := Identify(state)
	if err != nil {
		t.Fatal(err)
	}
	aliasIdentity, err := Identify(alias)
	if err != nil {
		t.Fatal(err)
	}
	if !stateIdentity.Overlaps(aliasIdentity) {
		t.Fatalf("bind-mounted ancestor was not detected: state=%q alias=%q", stateIdentity.scope, aliasIdentity.scope)
	}

	if err := unix.Mount(stateChild, childAlias, "", unix.MS_BIND, ""); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Unmount(childAlias, unix.MNT_DETACH) })
	childIdentity, err := Identify(childAlias)
	if err != nil {
		t.Fatal(err)
	}
	if !stateIdentity.Overlaps(childIdentity) {
		t.Fatalf("bind-mounted descendant was not detected: state=%q child=%q", stateIdentity.scope, childIdentity.scope)
	}
}

func TestLinuxIdentityDetectsNestedBindMount(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "state")
	export := filepath.Join(root, "export")
	nested := filepath.Join(export, ".state")
	for _, directory := range []string{state, nested} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := unix.Mount(state, nested, "", unix.MS_BIND, ""); err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skip("bind mounts require CAP_SYS_ADMIN")
		}
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Unmount(nested, unix.MNT_DETACH) })

	stateIdentity, err := Identify(state)
	if err != nil {
		t.Fatal(err)
	}
	exportIdentity, err := Identify(export)
	if err != nil {
		t.Fatal(err)
	}
	if !exportIdentity.Overlaps(stateIdentity) {
		t.Fatalf("nested state bind mount was not detected: state=%q export=%q nested=%v", stateIdentity.scope, exportIdentity.scope, exportIdentity.mountedScopes)
	}
}

func TestLinuxRejectsProcfsExports(t *testing.T) {
	for _, path := range []string{"/proc", filepath.Join("/proc", strconv.Itoa(os.Getpid()))} {
		identity, err := Identify(path)
		if err != nil {
			t.Fatalf("identify %s: %v", path, err)
		}
		if err := identity.ValidateExport(); err == nil || !strings.Contains(err.Error(), "proc") {
			t.Errorf("validate %s error = %v, want restricted procfs", path, err)
		}
	}

	hub, err := NewHub()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hub.Close() })
	if _, _, err := hub.Prepare("proc", "/proc", true); err == nil || !strings.Contains(err.Error(), "proc") {
		t.Fatalf("prepare procfs error = %v, want restricted procfs", err)
	}
	if _, err := NewServer("proc", "/proc", true); err == nil || !strings.Contains(err.Error(), "proc") {
		t.Fatalf("new procfs server error = %v, want restricted procfs", err)
	}
}

func TestLinuxRejectsNestedProcfsMount(t *testing.T) {
	export := t.TempDir()
	nested := filepath.Join(export, "proc")
	if err := os.Mkdir(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount("/proc", nested, "", unix.MS_BIND, ""); err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skip("bind mounts require CAP_SYS_ADMIN")
		}
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Unmount(nested, unix.MNT_DETACH) })

	identity, err := Identify(export)
	if err != nil {
		t.Fatal(err)
	}
	if err := identity.ValidateExport(); err == nil || !strings.Contains(err.Error(), "proc") {
		t.Fatalf("nested procfs validation error = %v", err)
	}
}

func TestLinuxMountScopeResolvesBindSource(t *testing.T) {
	const mountInfo = "36 25 8:1 / / rw - ext4 /dev/root rw\n" +
		"42 36 8:1 /real/gantry /mnt/gantry rw - ext4 /dev/root rw\n"

	normal, err := linuxMountScopeFromInfo(mountInfo, 36, "/real/gantry/sandboxes/dev")
	if err != nil {
		t.Fatal(err)
	}
	alias, err := linuxMountScopeFromInfo(mountInfo, 42, "/mnt/gantry/sandboxes/dev")
	if err != nil {
		t.Fatal(err)
	}
	if normal != alias {
		t.Fatalf("normal scope %q differs from bind scope %q", normal, alias)
	}
}

func TestLinuxMountedScopesResolveNestedSources(t *testing.T) {
	const mountInfo = "36 25 8:1 / / rw - ext4 /dev/root rw\n" +
		"42 36 8:1 /real/state /srv/export/.state rw - ext4 /dev/root rw\n" +
		"43 36 9:2 /elsewhere /srv/unrelated rw - ext4 /dev/other rw\n"

	scopes, err := linuxMountedScopesFromInfo(mountInfo, 36, "/srv/export")
	if err != nil {
		t.Fatal(err)
	}
	wantVolume := unix.Mkdev(8, 1)
	if len(scopes) != 1 || scopes[0].path != "/real/state" || scopes[0].volume != wantVolume || scopes[0].filesystem != "ext4" {
		t.Fatalf("nested scopes = %#v, want ext4 state scope on volume %d", scopes, wantVolume)
	}
}

func TestDecodeMountInfoPath(t *testing.T) {
	got, err := decodeMountInfoPath(`/path\040with\011escapes\134tail`)
	if err != nil {
		t.Fatal(err)
	}
	if want := "/path with\tescapes\\tail"; got != want {
		t.Fatalf("decoded path = %q, want %q", got, want)
	}
}
