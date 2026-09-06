// Package config contains persisted sandbox settings and typed launch inputs.
package config

import (
	"os"

	"github.com/ejpir/gantry/internal/guestasset"
)

// RunOptions is a transport-independent launch input. Start with DefaultRunOptions.
// Explicit records presence separately from value: an explicit false or default
// resource value must survive the CLI, HTTP, and dashboard adapters.
type RunOptions struct {
	Name             string
	Kernel           string
	Rootfs           string
	Runtime          string
	Image            string
	RWLayer          string
	LayerSet         string
	GVProxy          string
	NetPol           string
	ProxyURL         string
	NoProxy          string
	MCPFSRoot        string
	MCPFSUser        string
	ProcessIsolation string
	RW               bool
	Net              bool
	AllowLN          bool
	ProxyEnforce     bool
	OAuthBridge      bool
	OAuthCustody     bool
	MCP              bool
	SSH              bool
	DevContainers    bool
	RWLayerSizeMiB   uint
	MemMB            uint
	VCPUs            int
	Shares           []string
	Publish          []string
	MCPRemotes       []string
	Secrets          []string
	SecretFiles      []string
	Explicit         ExplicitOptions
}

type ExplicitOptions struct {
	Kernel, Rootfs, RW, Memory, CPUs, DiskSize bool
}

// DefaultRunOptions supplies the common defaults. Frontends may deliberately
// override policy (the manager API, for example, defaults to read-only).
func DefaultRunOptions() RunOptions {
	runtime := os.Getenv("GANTRY_RUNTIME")
	if runtime == "" {
		runtime = "crun"
	}
	return RunOptions{
		Kernel: guestasset.DefaultKernel(), Rootfs: guestasset.DefaultRootfs(),
		Runtime: runtime, RWLayerSizeMiB: DefaultRWLayerSizeMiB,
		Net: true, OAuthBridge: true, MCPFSRoot: "/", MCPFSUser: "nobody",
		ProcessIsolation: "auto", MemMB: 512, VCPUs: 1,
	}
}
