// Package vnet embeds gvisor-tap-vsock's virtual network stack in-process:
// gateway, DHCP, DNS, and NAT via gVisor netstack — everything the external
// gvproxy subprocess provided, with no binary to ship or port to babysit.
//
// The defaults mirror cmd/gvproxy's (subnet 192.168.127.0/24, gateway .1,
// host at .254, containers.internal/docker.internal zones), so vminitd's
// DHCP behaves exactly as it did against the subprocess. The guest MAC is
// pinned to 192.168.127.2 via a static lease (gvproxy hardcodes the same
// lease for its default MAC).
package vnet

import (
	"context"
	"fmt"
	"net"

	"github.com/containers/gvisor-tap-vsock/pkg/types"
	"github.com/containers/gvisor-tap-vsock/pkg/virtualnetwork"

	"gantry/internal/gutil"
)

const (
	SubnetCIDR  = "192.168.127.0/24"
	GatewayIP   = "192.168.127.1"
	GatewayMAC  = "5a:94:ef:e4:0c:dd"
	HostIP      = "192.168.127.254"
	GuestIP     = "192.168.127.2"
	DefaultMTU  = 1500
	dnsZoneHost = "host"
	dnsZoneGw   = "gateway"
)

// Stack is the host-side virtual network. Close shuts down its goroutines.
type Stack struct {
	vn     *virtualnetwork.VirtualNetwork
	ctx    context.Context
	cancel context.CancelFunc
}

// Start brings up the embedded network stack for one guest with the given
// MAC address. GANTRY_NET_PCAP=/path/file.pcap captures all traffic
// (Wireshark-readable); GANTRY_DEBUG_NET prints packets on stderr.
func Start(guestMAC [6]byte) (*Stack, error) {
	debug := gutil.EnvOr("GANTRY_DEBUG_NET", "MINIVM_DEBUG_NET") != ""
	cfg := &types.Configuration{
		Debug:             debug,
		MTU:               DefaultMTU,
		Subnet:            SubnetCIDR,
		GatewayIP:         GatewayIP,
		GatewayMacAddress: GatewayMAC,
		// the host itself, reachable from the guest as ...254
		NAT:               map[string]string{HostIP: "127.0.0.1"},
		GatewayVirtualIPs: []string{HostIP},
		DNS: []types.Zone{
			{
				Name: "containers.internal.",
				Records: []types.Record{
					{Name: dnsZoneGw, IP: net.ParseIP(GatewayIP)},
					{Name: dnsZoneHost, IP: net.ParseIP(HostIP)},
				},
			},
			{
				Name: "docker.internal.",
				Records: []types.Record{
					{Name: dnsZoneGw, IP: net.ParseIP(GatewayIP)},
					{Name: dnsZoneHost, IP: net.ParseIP(HostIP)},
				},
			},
		},
		// pin the guest to .2 regardless of -net-mac (gvproxy does this for
		// its default MAC; we do it for whichever MAC was chosen)
		DHCPStaticLeases: map[string]string{
			GuestIP: net.HardwareAddr(guestMAC[:]).String(),
		},
		Protocol: types.QemuProtocol,
	}
	if pcap := gutil.EnvOr("GANTRY_NET_PCAP", "MINIVM_NET_PCAP"); pcap != "" {
		cfg.CaptureFile = pcap
	}

	vn, err := virtualnetwork.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("embedded netstack: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Stack{vn: vn, ctx: ctx, cancel: cancel}, nil
}

// Dial returns one endpoint of an in-memory link to the stack. The caller
// (the virtio-net device) speaks the QEMU protocol on it: 4-byte big-endian
// length prefix + raw Ethernet frame — no handshake, unlike vfkit.
func (s *Stack) Dial() (net.Conn, error) {
	dev, gw := net.Pipe()
	go func() {
		// AcceptQemu blocks until the ctx is cancelled or the conn closes.
		if err := s.vn.AcceptQemu(s.ctx, gw); err != nil {
			dev.Close()
		}
	}()
	return dev, nil
}

// Close stops the stack's goroutines.
func (s *Stack) Close() { s.cancel() }
