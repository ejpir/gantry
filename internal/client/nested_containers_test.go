package client

import (
	"slices"
	"testing"

	"github.com/ejpir/gantry/internal/image"
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

func TestNestedContainersConfigDoesNotGiveNonRootCapabilities(t *testing.T) {
	base, err := configJSON(nil, true, []string{"true"}, &image.Config{User: "gantry", UID: 1000, GID: 1000}, false)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := nestedContainersConfig(base)
	if err != nil {
		t.Fatal(err)
	}
	config := decodeRuntimeConfig(t, encoded)
	if config.Process.Capabilities != nil {
		t.Fatalf("non-root process gained capabilities: %+v", config.Process.Capabilities)
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
