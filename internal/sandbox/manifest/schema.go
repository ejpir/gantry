// Package manifest defines Gantry's versioned, user-facing sandbox manifest.
// It describes intent only; fully resolved runtime state remains owned by the
// sandbox configuration package.
package manifest

import "github.com/ejpir/gantry/internal/sandbox/config"

const (
	APIVersion       = "gantry.dev/v1alpha1"
	Kind             = "Sandbox"
	maxManifestBytes = 1 << 20
)

// Document is one versioned sandbox declaration.
type Document struct {
	APIVersion string   `yaml:"apiVersion"`
	Kind       string   `yaml:"kind"`
	Metadata   Metadata `yaml:"metadata"`
	Spec       Spec     `yaml:"spec"`
}

type Metadata struct {
	Name string `yaml:"name"`
}

type Spec struct {
	Image              string              `yaml:"image,omitempty"`
	Runtime            string              `yaml:"runtime,omitempty"`
	Resources          *Resources          `yaml:"resources,omitempty"`
	Root               *Root               `yaml:"root,omitempty"`
	Boot               *Boot               `yaml:"boot,omitempty"`
	Shares             []Share             `yaml:"shares,omitempty"`
	Network            *Network            `yaml:"network,omitempty"`
	Secrets            []Secret            `yaml:"secrets,omitempty"`
	OrganizationPolicy *OrganizationPolicy `yaml:"organizationPolicy,omitempty"`
	OAuth              *OAuth              `yaml:"oauth,omitempty"`
	MCP                *MCP                `yaml:"mcp,omitempty"`
	SSH                *Feature            `yaml:"ssh,omitempty"`
	DevContainers      *Feature            `yaml:"devContainers,omitempty"`
	ProcessIsolation   string              `yaml:"processIsolation,omitempty"`
}

type Resources struct {
	CPUs   *int   `yaml:"cpus,omitempty"`
	Memory string `yaml:"memory,omitempty"`
	Disk   string `yaml:"disk,omitempty"`
}

type Root struct {
	Writable     *bool     `yaml:"writable,omitempty"`
	Layer        string    `yaml:"layer,omitempty"`
	LayerSetFile string    `yaml:"layerSetFile,omitempty"`
	LayerSet     *LayerSet `yaml:"layerSet,omitempty"`
}

type LayerSet struct {
	FSMeta string   `yaml:"fsmeta"`
	Layers []string `yaml:"layers"`
}

type Boot struct {
	Kernel string `yaml:"kernel,omitempty"`
	Rootfs string `yaml:"rootfs,omitempty"`
}

type Share struct {
	Name     string  `yaml:"name"`
	Source   string  `yaml:"source"`
	Target   string  `yaml:"target,omitempty"`
	ReadOnly bool    `yaml:"readOnly,omitempty"`
	UID      *uint32 `yaml:"uid,omitempty"`
	GID      *uint32 `yaml:"gid,omitempty"`
}

type Network struct {
	Enabled    *bool  `yaml:"enabled,omitempty"`
	AllowLocal bool   `yaml:"allowLocal,omitempty"`
	Policy     string `yaml:"policy,omitempty"`
	Ports      []Port `yaml:"ports,omitempty"`
	Proxy      *Proxy `yaml:"proxy,omitempty"`
}

type Port struct {
	Host     string `yaml:"host,omitempty"`
	Guest    uint16 `yaml:"guest"`
	Protocol string `yaml:"protocol,omitempty"`
}

type Proxy struct {
	URL     string   `yaml:"url"`
	NoProxy []string `yaml:"noProxy,omitempty"`
	Enforce bool     `yaml:"enforce,omitempty"`
}

type Secret struct {
	Name        string `yaml:"name"`
	Environment string `yaml:"environment,omitempty"`
	File        string `yaml:"file,omitempty"`
	Bind        string `yaml:"bind,omitempty"`
	TTL         string `yaml:"ttl,omitempty"`
}

type OrganizationPolicy struct {
	Bundle    string          `yaml:"bundle,omitempty"`
	PublicKey string          `yaml:"publicKey,omitempty"`
	Profile   string          `yaml:"profile,omitempty"`
	Snapshot  *PolicySnapshot `yaml:"snapshot,omitempty"`
}

type PolicySnapshot struct {
	BundleBase64 string `yaml:"bundleBase64"`
	PublicKey    string `yaml:"publicKey"`
	Profile      string `yaml:"profile"`
}

type OAuth struct {
	Bridge        *bool           `yaml:"bridge,omitempty"`
	Custody       bool            `yaml:"custody,omitempty"`
	ProviderFiles []string        `yaml:"providerFiles,omitempty"`
	Providers     []OAuthProvider `yaml:"providers,omitempty"`
}

type OAuthProvider struct {
	Name                   string   `yaml:"name"`
	Grant                  string   `yaml:"grant,omitempty"`
	AuthorizeURL           string   `yaml:"authorizeURL,omitempty"`
	DeviceAuthorizationURL string   `yaml:"deviceAuthorizationURL,omitempty"`
	TokenURL               string   `yaml:"tokenURL"`
	ClientID               string   `yaml:"clientID"`
	RedirectURI            string   `yaml:"redirectURI,omitempty"`
	Scope                  string   `yaml:"scope,omitempty"`
	Resource               string   `yaml:"resource,omitempty"`
	ExchangeEncoding       string   `yaml:"exchangeEncoding,omitempty"`
	RefreshEncoding        string   `yaml:"refreshEncoding,omitempty"`
	CredentialHosts        []string `yaml:"credentialHosts,omitempty"`
}

type MCP struct {
	Enabled    *bool       `yaml:"enabled,omitempty"`
	Filesystem *MCPFS      `yaml:"filesystem,omitempty"`
	Remotes    []MCPRemote `yaml:"remotes,omitempty"`
}

type MCPFS struct {
	Root string `yaml:"root,omitempty"`
	User string `yaml:"user,omitempty"`
}

type MCPRemote struct {
	Name   string   `yaml:"name"`
	URL    string   `yaml:"url"`
	Auth   *MCPAuth `yaml:"auth,omitempty"`
	Allow  []string `yaml:"allow,omitempty"`
	Deny   []string `yaml:"deny,omitempty"`
	Redact []string `yaml:"redact,omitempty"`
}

type MCPAuth struct {
	Type      string `yaml:"type"`
	Reference string `yaml:"reference"`
	Header    string `yaml:"header,omitempty"`
}

type Feature struct {
	Enabled bool `yaml:"enabled"`
}

// Compiled is a normalized manifest and its transport-independent launch input.
type Compiled struct {
	Document Document
	Options  config.RunOptions
}
