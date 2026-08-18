package sandbox

import (
	"fmt"
	"net"
	"os"

	"github.com/ejpir/gantry/internal/gutil"
	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/vmm"
)

// guestNetMAC is the fixed MAC the embedded netstack expects the guest to
// use (gvproxy-compatible pairing with the gateway MAC).
var guestNetMAC = [6]byte{0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee}

// Opts assembles vmm.Opts for the run. vsockFwd is the per-run socket
// directory. envExtra enables the GANTRY_EXTRA_CMDLINE debug knob (the
// daemon path; one-shot exec takes its cmdline exactly as resolved).
//
// All boot assets are opened HERE, up front: the returned Opts carries
// open descriptors, so the kernel/rootfs/layers a VM boots from are
// exactly the files that were resolved and validated — no path can be
// swapped between staging and boot, and a confined VMM worker needs no
// open-by-path rights at all. On success the Opts owns the files
// (Prepare consumes them); on error Opts closes what it opened.
func vmmOpts(c config.RunConfig, n *Network, vsockFwd string, envExtra bool) (vmm.Opts, error) {
	var o vmm.Opts
	fail := func(err error) (vmm.Opts, error) {
		for _, f := range append(append([]*os.File{o.Kernel, o.Initrd, o.Rootfs}, o.DisksRO...), o.Disks...) {
			if f != nil {
				_ = f.Close()
			}
		}
		return vmm.Opts{}, err
	}
	openRO := func(path, what string) (*os.File, error) {
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("%s %s: %w", what, path, err)
		}
		return f, nil
	}

	kernel, err := openRO(c.Kernel, "kernel")
	if err != nil {
		return fail(err)
	}
	o.Kernel = kernel
	arch, err := vmm.KernelArchFile(kernel)
	if err != nil {
		return fail(err)
	}
	if c.Rootfs != "" {
		if o.Rootfs, err = openRO(c.Rootfs, "rootfs"); err != nil {
			return fail(err)
		}
	}
	disksRO := []string{c.Image}
	if c.LayerSet != nil {
		disksRO = c.LayerSet.DisksRO()
	}
	for _, p := range disksRO {
		if p == "" {
			continue
		}
		f, err := openRO(p, "image layer")
		if err != nil {
			return fail(err)
		}
		o.DisksRO = append(o.DisksRO, f)
	}
	if c.RW && c.RWLayer != "" {
		f, err := os.OpenFile(c.RWLayer, os.O_RDWR, 0) // writable: /dev/vdc
		if err != nil {
			return fail(fmt.Errorf("rwlayer %s: %w", c.RWLayer, err))
		}
		o.Disks = append(o.Disks, f)
	}

	var sock string
	var conn net.Conn
	if n != nil {
		sock, conn = n.Sock, n.Conn
		// Interface fields: a typed-nil *netpol.Policy would read as a
		// non-nil PacketPolicy at the device boundary, so only assign what
		// actually exists.
		if !n.Split {
			if n.Policy != nil {
				o.NetPolicy = n.Policy
			}
			if n.Traffic != nil {
				o.NetTraffic = n.Traffic
			}
		}
	}
	memSize := uint64(c.MemMB) << 20
	cmdline := vmm.DefaultCmdline(arch, c.Rootfs, "", 3, NetMarker(sock, conn), guestNetMAC, true)
	cmdline = vmm.WithDeferredSMP(cmdline, c.VCPUs, memSize)
	if envExtra {
		cmdline = gutil.InsertExtraCmdline(cmdline)
	}
	o.MemSize = memSize
	o.NetEndpoint = sock
	o.NetConn = conn
	o.NetMAC = guestNetMAC
	o.NetVFKIT = true
	o.VsockFwd = vsockFwd
	o.VCPUs = c.VCPUs
	o.GuestCID = 3
	o.VsockListen = []uint32{1026}
	o.Cmdline = cmdline
	return o, nil
}
