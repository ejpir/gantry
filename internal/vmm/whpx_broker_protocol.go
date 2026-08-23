//go:build windows

package vmm

// WHPXBrokerConfig is the supervisor-authenticated resource ceiling for the
// narrow Windows hypervisor broker. The peer token correlates the broker with
// exactly one AppContainer device worker.
type WHPXBrokerConfig struct {
	MemSize   uint64 `json:"memSize"`
	VCPUs     int    `json:"vcpus"`
	PeerToken string `json:"peerToken"`
}

type whpxBrokerRegion struct {
	GuestBase  uint64 `json:"guestBase"`
	HostOffset uint64 `json:"hostOffset"`
	Size       uint64 `json:"size"`
}

type whpxBrokerSetup struct {
	VCPUs   int                `json:"vcpus"`
	Entry   uint64             `json:"entry"`
	Initial []whpxBrokerRegion `json:"initial"`
	Hot     *whpxBrokerRegion  `json:"hot,omitempty"`
}

type whpxBrokerExit struct {
	ID      uint64   `json:"id"`
	VCPU    uint32   `json:"vcpu"`
	Context []byte   `json:"context"`
	GPRs    []uint64 `json:"gprs,omitempty"`
}

type whpxBrokerReply struct {
	ID             uint64   `json:"id"`
	RegisterNames  []uint32 `json:"registerNames,omitempty"`
	RegisterValues []uint64 `json:"registerValues,omitempty"`
	Stop           bool     `json:"stop,omitempty"`
	Error          string   `json:"error,omitempty"`
}

type whpxBrokerInterrupt struct {
	Destination uint32 `json:"destination"`
	Vector      uint32 `json:"vector"`
	Level       bool   `json:"level,omitempty"`
}

type whpxBrokerEnvelope struct {
	Type      string               `json:"type"`
	Token     string               `json:"token,omitempty"`
	Setup     *whpxBrokerSetup     `json:"setup,omitempty"`
	Interrupt *whpxBrokerInterrupt `json:"interrupt,omitempty"`
	ID        uint64               `json:"id,omitempty"`
	Error     string               `json:"error,omitempty"`
}

type WHPXBrokerBootAck struct {
	OK                      bool   `json:"ok"`
	Error                   string `json:"error,omitempty"`
	ProcessorClockFrequency uint64 `json:"processorClockFrequency,omitempty"`
}
