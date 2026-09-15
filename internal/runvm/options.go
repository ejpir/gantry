// Package runvm shares the low-level VM launch flags between local and remote
// adapters. The wire type is canonical in managerapi; execution remains in the
// existing Gantry run command, with its file-pinning and share restrictions.
package runvm

import (
	"flag"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/ejpir/gantry/api/managerapi"
	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/shares"
)

const (
	MaxStdinBytes     = 64 << 10
	MaxOutputBytes    = 64 << 10 // retained operation history stays bounded too
	MaxTimeoutSeconds = 3600
)

func Defaults() managerapi.RunVMRequest {
	vfkit, dhcp, ports := true, true, "1026"
	return managerapi.RunVMRequest{NetworkMAC: "5a:94:ef:e4:0c:ee", NetworkVFKIT: &vfkit, NetworkDHCP: &dhcp,
		VsockListen: &ports, GuestCID: 3, MemoryMiB: 512, CPUs: 1, TimeoutSeconds: 300, MaxOutputBytes: 16 << 10}
}

// BindFlags is shared by both CLIs. It does no host I/O, so a remote path is
// never inspected, opened or interpreted on the client machine.
func BindFlags(fs *flag.FlagSet) *managerapi.RunVMRequest {
	r := Defaults()
	fs.StringVar(&r.Kernel, "kernel", "", "path to Linux kernel (required)")
	fs.StringVar(&r.Initrd, "initrd", "", "path to initramfs cpio.gz")
	fs.StringVar(&r.Rootfs, "rootfs", "", "rootfs image attached as /dev/vda")
	fs.Func("disk", "extra virtio-blk image (repeatable)", func(s string) error { r.Disks = append(r.Disks, s); return nil })
	fs.Func("share", "host share TAG=PATH[,mount=CTRPATH][,ro] (repeatable)", func(s string) error { r.Shares = append(r.Shares, s); return nil })
	fs.StringVar(&r.NetworkEndpoint, "net", "", "Unix datagram raw-Ethernet backend path")
	fs.StringVar(&r.NetworkMAC, "net-mac", r.NetworkMAC, "virtio-net MAC address")
	r.NetworkVFKIT = fs.Bool("net-vfkit", true, "send VFKT registration to network backend")
	r.NetworkDHCP = fs.Bool("net-dhcp", true, "configure the guest interface using DHCP")
	fs.StringVar(&r.VsockForward, "vsockfwd", "", "host directory for vsock forwarding")
	fs.Uint64Var(&r.GuestCID, "guestcid", r.GuestCID, "guest vsock context ID")
	r.VsockListen = fs.String("vsocklisten", "1026", "comma-separated guest ports accepting host connections")
	fs.UintVar(&r.MemoryMiB, "mem", r.MemoryMiB, "guest RAM in MiB")
	fs.IntVar(&r.CPUs, "cpus", r.CPUs, "guest vCPU count")
	fs.StringVar(&r.CommandLine, "append", "", "kernel command line (default depends on boot assets)")
	return &r
}

func Validate(r managerapi.RunVMRequest) error {
	if r.Kernel == "" || r.Initrd == "" && r.Rootfs == "" {
		return fmt.Errorf("-kernel and at least one of -initrd/-rootfs are required")
	}
	if err := config.ValidateSandboxResourceBounds(r.MemoryMiB, r.CPUs); err != nil {
		return err
	}
	if r.TimeoutSeconds < 1 || r.TimeoutSeconds > MaxTimeoutSeconds {
		return fmt.Errorf("timeoutSeconds must be between 1 and %d", MaxTimeoutSeconds)
	}
	if r.MaxOutputBytes < 1 || r.MaxOutputBytes > MaxOutputBytes {
		return fmt.Errorf("maxOutputBytes must be between 1 and %d", MaxOutputBytes)
	}
	if len(r.Stdin) > MaxStdinBytes {
		return fmt.Errorf("stdin exceeds %d bytes", MaxStdinBytes)
	}
	if len(r.Disks) > 16 || len(r.Shares) > 16 {
		return fmt.Errorf("at most 16 disks and 16 shares are allowed")
	}
	values := []string{r.Kernel, r.Initrd, r.Rootfs, r.NetworkEndpoint, r.NetworkMAC, r.VsockForward, r.CommandLine}
	if r.VsockListen != nil {
		values = append(values, *r.VsockListen)
	}
	values = append(values, r.Disks...)
	values = append(values, r.Shares...)
	for _, value := range values {
		if len(value) > 4096 || strings.ContainsRune(value, 0) {
			return fmt.Errorf("run fields must not contain NUL or exceed 4096 bytes")
		}
	}
	for _, disk := range r.Disks {
		if disk == "" {
			return fmt.Errorf("disk paths must not be empty")
		}
	}
	if r.NetworkEndpoint != "" {
		mac, err := net.ParseMAC(r.NetworkMAC)
		if err != nil || len(mac) != 6 {
			return fmt.Errorf("invalid network MAC address")
		}
	}
	if r.VsockForward != "" && r.VsockListen != nil && *r.VsockListen != "" {
		if _, err := ParseListenPorts(*r.VsockListen); err != nil {
			return err
		}
	}
	if _, err := shares.ParseSpecs(r.Shares); err != nil {
		return fmt.Errorf("invalid share: %w", err)
	}
	return nil
}

// Args constructs a fixed allowlist, never a shell command or caller-provided
// argv. -remote= deliberately defeats a manager's inherited remote default.
func Args(r managerapi.RunVMRequest) []string {
	// Equals forms also keep flag-looking values out of the global selector
	// scanner (for example a command line beginning with "-remote=").
	args := []string{"run", "-remote=", "-kernel=" + r.Kernel, "-initrd=" + r.Initrd, "-rootfs=" + r.Rootfs,
		"-net=" + r.NetworkEndpoint, "-net-mac=" + r.NetworkMAC, "-vsockfwd=" + r.VsockForward,
		"-guestcid=" + strconv.FormatUint(r.GuestCID, 10), "-mem=" + strconv.FormatUint(uint64(r.MemoryMiB), 10),
		"-cpus=" + strconv.Itoa(r.CPUs), "-append=" + r.CommandLine}
	if r.NetworkVFKIT != nil {
		args = append(args, "-net-vfkit="+strconv.FormatBool(*r.NetworkVFKIT))
	}
	if r.NetworkDHCP != nil {
		args = append(args, "-net-dhcp="+strconv.FormatBool(*r.NetworkDHCP))
	}
	if r.VsockListen != nil {
		args = append(args, "-vsocklisten="+*r.VsockListen)
	}
	for _, disk := range r.Disks {
		args = append(args, "-disk="+disk)
	}
	for _, share := range r.Shares {
		args = append(args, "-share="+share)
	}
	return args
}

func ParseListenPorts(value string) ([]uint32, error) {
	var ports []uint32
	for _, part := range strings.Split(value, ",") {
		n, err := strconv.ParseUint(strings.TrimSpace(part), 10, 32)
		if err != nil || n == 0 {
			return nil, fmt.Errorf("invalid vsock port %q (must be 1..4294967295)", part)
		}
		ports = append(ports, uint32(n))
	}
	return ports, nil
}
