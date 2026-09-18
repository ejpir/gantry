package netpol

import "time"

const (
	// TrafficFileName is stored in each sandbox directory and intentionally
	// survives stop/resume cycles alongside sandbox.json.
	TrafficFileName         = "network-traffic.json"
	trafficSnapshotVersion  = 1
	maxTrafficEntries       = 512
	maxTrafficDNSNames      = 4096
	maxTrafficHostBytes     = 253
	maxTrafficAddressBytes  = 64
	maxTrafficProtocolBytes = 16
)

// TrafficSnapshot is the on-disk, read-only dashboard view of one VM's
// network activity. Byte and packet directions are from the guest's point of
// view: TX leaves the VM and RX enters it. Blocked traffic is counted in TX
// and separately in Dropped* because the guest did attempt to send it.
type TrafficSnapshot struct {
	Version        int            `json:"version"`
	Updated        time.Time      `json:"updated"`
	TXBytes        uint64         `json:"txBytes"`
	RXBytes        uint64         `json:"rxBytes"`
	TXPackets      uint64         `json:"txPackets"`
	RXPackets      uint64         `json:"rxPackets"`
	DroppedBytes   uint64         `json:"droppedBytes"`
	DroppedPackets uint64         `json:"droppedPackets"`
	Entries        []TrafficEntry `json:"entries"`
}

// TrafficEntry aggregates packets for a destination, protocol, port and
// policy decision. Host is a best-effort DNS name learned from responses;
// Address always retains the numeric peer address.
type TrafficEntry struct {
	Host      string    `json:"host"`
	Address   string    `json:"address"`
	Protocol  string    `json:"protocol"`
	Port      uint16    `json:"port,omitempty"`
	Allowed   bool      `json:"allowed"`
	TXBytes   uint64    `json:"txBytes"`
	RXBytes   uint64    `json:"rxBytes"`
	TXPackets uint64    `json:"txPackets"`
	RXPackets uint64    `json:"rxPackets"`
	FirstSeen time.Time `json:"firstSeen"`
	LastSeen  time.Time `json:"lastSeen"`
}
