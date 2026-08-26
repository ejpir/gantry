package client

import (
	"encoding/json"
	"fmt"

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

var nestedContainerMounts = []specs.Mount{
	// The ordinary Gantry /dev is intentionally minimal. Expose only the two
	// kernel devices required by slirp4netns and fuse-overlayfs, never host block
	// devices or a container-engine socket.
	{Destination: "/dev/fuse", Type: "bind", Source: "/dev/fuse", Options: []string{"rbind", "rprivate", "rw"}},
	{Destination: "/dev/net/tun", Type: "bind", Source: "/dev/net/tun", Options: []string{"rbind", "rprivate", "rw"}},
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
	config.Mounts = append(config.Mounts, nestedContainerMounts...)
	if config.Annotations == nil {
		config.Annotations = make(map[string]string)
	}
	config.Annotations[nestedContainersAnnotation] = "v1"

	if config.Process.User.UID != 0 {
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
