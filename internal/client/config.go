package client

import (
	"encoding/json"
	"strings"

	"github.com/ejpir/gantry/internal/image"
	"github.com/ejpir/gantry/internal/shares"

	"github.com/containerd/containerd/api/types"
	"github.com/opencontainers/runtime-spec/specs-go"
)

var containerCapabilities = []string{
	"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FSETID", "CAP_FOWNER",
	"CAP_MKNOD", "CAP_NET_RAW", "CAP_SETGID", "CAP_SETUID", "CAP_SETFCAP",
	"CAP_SETPCAP", "CAP_NET_BIND_SERVICE", "CAP_SYS_CHROOT", "CAP_KILL",
	"CAP_AUDIT_WRITE",
}

var baseContainerMounts = []specs.Mount{
	{Destination: "/proc", Type: "proc", Source: "proc"},
	{Destination: "/dev", Type: "tmpfs", Source: "tmpfs", Options: []string{"nosuid", "strictatime", "mode=755", "size=65536k"}},
	{Destination: "/dev/pts", Type: "devpts", Source: "devpts", Options: []string{"nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620"}},
	{Destination: "/dev/shm", Type: "tmpfs", Source: "shm", Options: []string{"nosuid", "noexec", "nodev", "mode=1777", "size=65536k"}},
	{Destination: "/dev/mqueue", Type: "mqueue", Source: "mqueue", Options: []string{"nosuid", "noexec", "nodev"}},
	{Destination: "/sys", Type: "sysfs", Source: "sysfs", Options: []string{"nosuid", "noexec", "nodev", "ro"}},
	{Destination: "/tmp", Type: "tmpfs", Source: "tmpfs", Options: []string{"nosuid", "nodev", "mode=1777"}},
	{Destination: "/etc/resolv.conf", Type: "bind", Source: "/etc/resolv.conf", Options: []string{"rbind", "rprivate", "ro"}},
	{Destination: "/etc/hosts", Type: "bind", Source: "/etc/hosts", Options: []string{"rbind", "rprivate", "ro"}},
}

type runtimeConfig struct {
	Version     string            `json:"ociVersion"`
	Process     runtimeProcess    `json:"process"`
	Root        runtimeRoot       `json:"root"`
	Hostname    string            `json:"hostname"`
	Mounts      []specs.Mount     `json:"mounts"`
	Linux       runtimeLinux      `json:"linux"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

type runtimeProcess struct {
	Terminal        bool                     `json:"terminal"`
	User            specs.User               `json:"user"`
	NoNewPrivileges bool                     `json:"noNewPrivileges,omitempty"`
	Args            []string                 `json:"args"`
	Env             []string                 `json:"env"`
	Cwd             string                   `json:"cwd"`
	Capabilities    *specs.LinuxCapabilities `json:"capabilities"`
	Rlimits         []specs.POSIXRlimit      `json:"rlimits"`
}

type runtimeRoot struct {
	Path     string `json:"path"`
	Readonly bool   `json:"readonly"`
}

type runtimeLinux struct {
	Namespaces    []specs.LinuxNamespace `json:"namespaces"`
	MaskedPaths   []string               `json:"maskedPaths"`
	ReadonlyPaths []string               `json:"readonlyPaths"`
}

// RootfsMountsFor describes how the guest assembles the container rootfs.
func (options SessionOptions) RootfsMountsFor() []*types.Mount {
	if options.LayerSet != nil {
		return RootfsMountsLayerSet(*options.LayerSet)
	}
	return RootfsMounts(options.RW)
}

// ConfigJSON renders a terminal OCI runtime configuration using the live
// per-device share transport.
func ConfigJSON(entries []ShareEntry, rw bool, args []string, img *image.Config) (string, error) {
	return configJSONWithTransport(entries, nil, rw, args, img, true)
}

// ConfigJSONWithTransport renders an OCI runtime configuration for either the
// versioned share hub or the current per-device direct-run transport.
func ConfigJSONWithTransport(entries []ShareEntry, transport *shares.Transport, rw bool, args []string, img *image.Config) (string, error) {
	return configJSONWithTransport(entries, transport, rw, args, img, true)
}

// configJSON renders the non-terminal long-lived sandbox init when terminal is
// false. The process then remains independent of any session pty.
func configJSON(entries []ShareEntry, rw bool, args []string, img *image.Config, terminal bool) (string, error) {
	return configJSONWithTransport(entries, nil, rw, args, img, terminal)
}

func configJSONWithTransport(entries []ShareEntry, transport *shares.Transport, rw bool, args []string, img *image.Config, terminal bool) (string, error) {
	return configJSONWithTransportCwd(entries, transport, rw, args, img, terminal, "")
}

func configJSONWithTransportCwd(entries []ShareEntry, transport *shares.Transport, rw bool, args []string, img *image.Config, terminal bool, cwd string) (string, error) {
	return configJSONWithTransportCwdEnv(entries, transport, rw, args, img, terminal, cwd, nil)
}

func configJSONWithTransportCwdEnv(entries []ShareEntry, transport *shares.Transport, rw bool, args []string, img *image.Config, terminal bool, cwd string, environment []string) (string, error) {
	uid, gid := img.IDs()
	if cwd == "" {
		cwd = img.WorkdirOr()
	}
	mounts := baseContainerMounts
	if transport != nil {
		// crun cannot create bind targets in a read-only EROFS root. The hub
		// remains mounted guest-side for shareless read-only workloads.
		if rw {
			mounts = appendMounts(baseContainerMounts, hubShareMounts(entries, transport))
		}
	} else if len(entries) != 0 {
		mounts = appendMounts(baseContainerMounts, perDeviceShareMounts(entries))
	}

	var capabilities *specs.LinuxCapabilities
	if uid == 0 {
		capabilities = &specs.LinuxCapabilities{
			Bounding:  containerCapabilities,
			Effective: containerCapabilities,
			Permitted: containerCapabilities,
		}
	}
	config := runtimeConfig{
		Version: "1.1.0",
		Process: runtimeProcess{
			Terminal:     terminal,
			User:         specs.User{UID: uid, GID: gid},
			Args:         args,
			Env:          processEnvironment(img, environment),
			Cwd:          cwd,
			Capabilities: capabilities,
			Rlimits:      []specs.POSIXRlimit{{Type: "RLIMIT_NOFILE", Hard: 65536, Soft: 65536}},
		},
		Root:     runtimeRoot{Path: "rootfs", Readonly: !rw},
		Hostname: "nerdbox",
		Mounts:   mounts,
		Linux: runtimeLinux{
			Namespaces: []specs.LinuxNamespace{
				{Type: specs.PIDNamespace},
				{Type: specs.IPCNamespace},
				{Type: specs.UTSNamespace},
				{Type: specs.MountNamespace},
			},
			MaskedPaths: []string{
				"/proc/acpi", "/proc/asound", "/proc/kcore", "/proc/keys",
				"/proc/latency_stats", "/proc/timer_list", "/proc/timer_stats",
				"/proc/sched_debug", "/sys/firmware", "/proc/scsi",
			},
			ReadonlyPaths: []string{
				"/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger",
			},
		},
	}
	encoded, err := json.Marshal(config)
	return string(encoded), err
}

func appendMounts(base, extra []specs.Mount) []specs.Mount {
	if len(extra) == 0 {
		return base
	}
	mounts := make([]specs.Mount, 0, len(base)+len(extra))
	mounts = append(mounts, base...)
	return append(mounts, extra...)
}

func perDeviceShareMounts(entries []ShareEntry) []specs.Mount {
	mounts := make([]specs.Mount, 0, len(entries)+1)
	for _, entry := range entries {
		if entry.CtrPath != shares.HubHostPath {
			mounts = append(mounts, specs.Mount{
				Destination: shares.HubHostPath,
				Type:        "tmpfs",
				Source:      "tmpfs",
				Options:     []string{"nosuid", "nodev", "rw"},
			})
			break
		}
	}
	for _, entry := range entries {
		mounts = append(mounts, bindMount(entry.CtrPath, entry.VMPath, entry.RO))
	}
	return mounts
}

// hubShareMounts binds the permanent hub into the long-lived container once.
// Logical children then remain visible to already-running processes.
func hubShareMounts(entries []ShareEntry, transport *shares.Transport) []specs.Mount {
	if transport == nil {
		return nil
	}
	mounts := make([]specs.Mount, 0, len(entries)+2)
	mounts = append(mounts, bindMount(shares.HubInternalPath, transport.VMPath, false))
	coverHost := false
	for _, entry := range entries {
		if shareContainerPath(entry) == shares.HubHostPath {
			coverHost = true
			break
		}
	}
	if !coverHost {
		mounts = append(mounts, bindMount(shares.HubHostPath, transport.VMPath, false))
	}
	root := strings.TrimRight(transport.VMPath, "/")
	for _, entry := range entries {
		destination := shareContainerPath(entry)
		if destination == shares.HubHostPath+"/"+entry.Tag || destination == shares.HubInternalPath+"/"+entry.Tag {
			continue
		}
		mounts = append(mounts, bindMount(destination, root+"/"+entry.Tag, entry.RO))
	}
	return mounts
}

func shareContainerPath(entry ShareEntry) string {
	if entry.CtrPath != "" {
		return entry.CtrPath
	}
	return shares.HubHostPath + "/" + entry.Tag
}

func bindMount(destination, source string, readOnly bool) specs.Mount {
	options := []string{"rbind", "rprivate"}
	if readOnly {
		options = append(options, "ro")
	}
	return specs.Mount{Destination: destination, Type: "bind", Source: source, Options: options}
}
