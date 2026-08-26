package client

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/opencontainers/runtime-spec/specs-go"
)

const nestedContainersAnnotation = "io.gantry.devcontainers.profile"

var nestedContainerCapabilities = []string{
	// An inner OCI runtime needs to create mount and network namespaces. These
	// capabilities exist only inside the selected sandbox microVM; the VM,
	// explicit host shares and Gantry's network worker remain the host
	// security boundaries.
	"CAP_NET_ADMIN",
	"CAP_SYS_ADMIN",
}

var nestedDeviceMode os.FileMode = 0o666

var nestedContainerDevices = []specs.LinuxDevice{
	// The ordinary Gantry /dev is intentionally minimal. Have the OCI runtime
	// create only the two kernel device nodes needed by fuse-overlayfs and
	// slirp4netns. Binding them from the VM root would make the profile depend
	// on distro-specific boot-time /dev population.
	{Path: "/dev/fuse", Type: "c", Major: 10, Minor: 229, FileMode: &nestedDeviceMode},
	{Path: "/dev/net/tun", Type: "c", Major: 10, Minor: 200, FileMode: &nestedDeviceMode},
}

var nestedContainerMounts = []specs.Mount{
	// Nested cgroup management is disabled in the curated image. A read-only
	// cgroup2 view is nevertheless required because inner crun validates the
	// filesystem mounted at this conventional path. Do not delegate the guest's
	// writable cgroup root to untrusted workspace code.
	{Destination: "/sys/fs/cgroup", Type: "bind", Source: "/sys/fs/cgroup", Options: []string{"rbind", "rprivate", "ro"}},
}

func nestedContainersConfig(encoded string) (string, error) {
	var config runtimeConfig
	if err := json.Unmarshal([]byte(encoded), &config); err != nil {
		return "", fmt.Errorf("decode devcontainers runtime config: %w", err)
	}
	applyNestedContainersRuntimeConfig(&config)
	result, err := json.Marshal(config)
	if err != nil {
		return "", fmt.Errorf("encode devcontainers runtime config: %w", err)
	}
	return string(result), nil
}

func applyNestedContainersRuntimeConfig(config *runtimeConfig) {
	if config == nil {
		return
	}
	config.Linux.RootfsPropagation = "rshared"
	config.Linux.Devices = append(config.Linux.Devices, nestedContainerDevices...)
	config.Mounts = append(config.Mounts, nestedContainerMounts...)
	if config.Annotations == nil {
		config.Annotations = make(map[string]string)
	}
	config.Annotations[nestedContainersAnnotation] = "v1"

	if config.Process.User.UID != 0 {
		// The curated image deliberately uses a non-root development user and a
		// setuid sudo wrapper for rootful Podman. Keep the user's effective and
		// permitted sets empty, but retain the profile's bounded capabilities so
		// the kernel can grant them only after the audited setuid transition.
		// The long-lived nobody anchor has no-new-privileges and must retain no
		// capability set at all.
		if config.Process.NoNewPrivileges {
			return
		}
		if config.Process.Capabilities == nil {
			config.Process.Capabilities = &specs.LinuxCapabilities{}
		}
		for _, capabilities := range [][]string{containerCapabilities, nestedContainerCapabilities} {
			for _, capability := range capabilities {
				config.Process.Capabilities.Bounding = appendUniqueString(config.Process.Capabilities.Bounding, capability)
			}
		}
		return
	}
	if config.Process.Capabilities == nil {
		config.Process.Capabilities = &specs.LinuxCapabilities{}
	}
	for _, capability := range nestedContainerCapabilities {
		config.Process.Capabilities.Bounding = appendUniqueString(config.Process.Capabilities.Bounding, capability)
		config.Process.Capabilities.Effective = appendUniqueString(config.Process.Capabilities.Effective, capability)
		config.Process.Capabilities.Permitted = appendUniqueString(config.Process.Capabilities.Permitted, capability)
	}
}

func appendUniqueString(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}
