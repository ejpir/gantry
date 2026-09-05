package client

import (
	"slices"
	"strings"
	"testing"

	"github.com/ejpir/gantry/internal/image"
	"github.com/opencontainers/runtime-spec/specs-go"
)

func TestNestedContainersConfigIsNarrowAndRootOnly(t *testing.T) {
	base, err := configJSON(nil, true, []string{"true"}, &image.Config{User: "root"}, false)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := nestedContainersConfig(base)
	if err != nil {
		t.Fatal(err)
	}
	config := decodeRuntimeConfig(t, encoded)
	if config.Linux.RootfsPropagation != "rshared" {
		t.Fatalf("rootfs propagation = %q, want rshared", config.Linux.RootfsPropagation)
	}
	for kind, paths := range map[string][]string{
		"masked":    config.Linux.MaskedPaths,
		"read-only": config.Linux.ReadonlyPaths,
	} {
		for _, path := range paths {
			if path == "/proc" || strings.HasPrefix(path, "/proc/") {
				t.Errorf("nested-runtime config retained %s proc path %q", kind, path)
			}
		}
	}
	if !slices.Contains(config.Linux.MaskedPaths, "/sys/firmware") {
		t.Error("nested-runtime config removed non-proc base mask /sys/firmware")
	}
	for _, expected := range nestedContainerDevices {
		var device *specs.LinuxDevice
		for index := range config.Linux.Devices {
			if config.Linux.Devices[index].Path == expected.Path {
				device = &config.Linux.Devices[index]
				break
			}
		}
		if device == nil || device.Type != "c" || device.Major != expected.Major || device.Minor != expected.Minor ||
			device.FileMode == nil || *device.FileMode != 0o666 {
			t.Errorf("device %s = %+v, want narrow character device %d:%d mode 0666", expected.Path, device, expected.Major, expected.Minor)
		}
		if mount := findMount(config.Mounts, expected.Path); mount != nil {
			t.Errorf("device %s unexpectedly depends on VM-root bind mount: %+v", expected.Path, mount)
		}
	}
	for _, expected := range nestedContainerMounts {
		mount := findMount(config.Mounts, expected.Destination)
		if mount == nil || mount.Type != "bind" || mount.Source != expected.Source {
			t.Errorf("mount %s = %+v, want narrow bind from %s", expected.Destination, mount, expected.Source)
		}
	}
	cgroup := findMount(config.Mounts, "/sys/fs/cgroup")
	if cgroup == nil || !slices.Contains(cgroup.Options, "ro") {
		t.Fatalf("cgroup mount = %+v, want read-only", cgroup)
	}
	for _, capability := range nestedContainerCapabilities {
		if !slices.Contains(config.Process.Capabilities.Bounding, capability) ||
			!slices.Contains(config.Process.Capabilities.Effective, capability) ||
			!slices.Contains(config.Process.Capabilities.Permitted, capability) {
			t.Errorf("root process missing %s: %+v", capability, config.Process.Capabilities)
		}
	}
	if config.Annotations[nestedContainersAnnotation] != "v1" {
		t.Fatalf("profile annotation = %q", config.Annotations[nestedContainersAnnotation])
	}
}

func TestNestedContainersConfigGivesNonRootOnlySudoBoundingSet(t *testing.T) {
	base, err := configJSON(nil, true, []string{"true"}, &image.Config{User: "gantry", UID: 1000, GID: 1000}, false)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := nestedContainersConfig(base)
	if err != nil {
		t.Fatal(err)
	}
	config := decodeRuntimeConfig(t, encoded)
	capabilities := config.Process.Capabilities
	if capabilities == nil {
		t.Fatal("non-root development process has no bounding set for setuid sudo")
	}
	for _, capability := range []string{"CAP_SETUID", "CAP_SETGID", "CAP_SYS_ADMIN", "CAP_NET_ADMIN"} {
		if !slices.Contains(capabilities.Bounding, capability) {
			t.Errorf("non-root development process bounding set is missing %s: %+v", capability, capabilities)
		}
	}
	if len(capabilities.Effective) != 0 || len(capabilities.Permitted) != 0 || len(capabilities.Ambient) != 0 {
		t.Fatalf("non-root development process received active capabilities: %+v", capabilities)
	}
}

func TestOrdinaryContainerAllowsNestedProcMount(t *testing.T) {
	encoded, err := configJSON(nil, true, []string{"true"}, &image.Config{User: "root"}, false)
	if err != nil {
		t.Fatal(err)
	}
	config := decodeRuntimeConfig(t, encoded)
	for kind, paths := range map[string][]string{
		"masked":    config.Linux.MaskedPaths,
		"read-only": config.Linux.ReadonlyPaths,
	} {
		for _, path := range paths {
			if path == "/proc" || strings.HasPrefix(path, "/proc/") {
				t.Errorf("ordinary config retained %s proc path %q", kind, path)
			}
		}
	}
	if !slices.Contains(config.Linux.MaskedPaths, "/sys/firmware") {
		t.Error("ordinary config removed non-proc mask /sys/firmware")
	}
	for _, capability := range []string{"CAP_SYS_ADMIN", "CAP_SYS_RAWIO", "CAP_SYS_PTRACE", "CAP_NET_ADMIN"} {
		if slices.Contains(config.Process.Capabilities.Bounding, capability) ||
			slices.Contains(config.Process.Capabilities.Effective, capability) ||
			slices.Contains(config.Process.Capabilities.Permitted, capability) {
			t.Errorf("ordinary config gained %s: %+v", capability, config.Process.Capabilities)
		}
	}
}

func TestNestedContainersAnchorRemainsUnprivileged(t *testing.T) {
	encoded, err := sandboxContainerConfig(SessionOptions{
		NestedContainers: true,
		ImgCfg:           &image.Config{User: "gantry", UID: 1000, GID: 1000},
	})
	if err != nil {
		t.Fatal(err)
	}
	config := decodeRuntimeConfig(t, encoded)
	if config.Process.User.UID != 65534 || !config.Process.NoNewPrivileges {
		t.Fatalf("anchor identity = %d noNewPrivileges=%v", config.Process.User.UID, config.Process.NoNewPrivileges)
	}
	if capabilities := config.Process.Capabilities; capabilities == nil ||
		len(capabilities.Bounding)+len(capabilities.Effective)+len(capabilities.Permitted) != 0 {
		t.Fatalf("anchor gained capabilities: %+v", capabilities)
	}
	if findMount(config.Mounts, "/sys/fs/cgroup") == nil {
		t.Fatal("anchor did not establish nested-runtime mounts")
	}
}
