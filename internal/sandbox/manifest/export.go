package manifest

import (
	"encoding/base64"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/ejpir/gantry/internal/mcpspec"
	"github.com/ejpir/gantry/internal/oauthprovider"
	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/secret"
	"github.com/ejpir/gantry/internal/shares"
)

func providerFromSpec(provider oauthprovider.Spec) OAuthProvider {
	return OAuthProvider{
		Name: provider.Provider, Grant: provider.Grant, AuthorizeURL: provider.AuthorizeURL,
		DeviceAuthorizationURL: provider.DeviceAuthorizationURL, TokenURL: provider.TokenURL,
		ClientID: provider.ClientID, RedirectURI: provider.RedirectURI, Scope: provider.Scope,
		Resource: provider.Resource, ExchangeEncoding: provider.ExchangeEncoding,
		RefreshEncoding: provider.RefreshEncoding, CredentialHosts: append([]string(nil), provider.CredentialHosts...),
	}
}

func remoteFromSpec(remote mcpspec.Remote) MCPRemote {
	out := MCPRemote{Name: remote.Name, URL: remote.URL, Allow: append([]string(nil), remote.Allow...), Deny: append([]string(nil), remote.Deny...), Redact: append([]string(nil), remote.RedactNames...)}
	if remote.AuthKind != "" {
		out.Auth = &MCPAuth{Type: remote.AuthKind, Reference: remote.AuthRef, Header: remote.AuthHeader}
	}
	return out
}

// FromConfig projects resolved internal state back into a redacted public
// manifest. Secret values are never present in RunConfig; value-only legacy
// entries become same-name environment references.
func FromConfig(name string, cfg config.RunConfig) (Document, error) {
	writable := cfg.RW
	networkEnabled := cfg.Net
	bridge, custody := cfg.OAuthBridgeEnabled(), cfg.OAuthCustodyEnabled()
	document := Document{
		APIVersion: APIVersion, Kind: Kind, Metadata: Metadata{Name: name},
		Spec: Spec{
			Runtime:   cfg.Runtime,
			Resources: &Resources{CPUs: intPointer(cfg.VCPUs), Memory: formatMiB(cfg.MemMB)},
			Root:      &Root{Writable: &writable, Layer: cfg.RWLayer},
			Boot:      &Boot{Rootfs: cfg.Rootfs},
			Network:   &Network{Enabled: &networkEnabled, AllowLocal: cfg.AllowLN, Policy: cfg.NetPol},
			SSH:       &Feature{Enabled: cfg.SSH}, DevContainers: &Feature{Enabled: cfg.DevContainers},
			ProcessIsolation: config.NormalizeProcessIsolation(cfg.ProcessIsolation),
		},
	}
	if cfg.RWLayerSizeMiB != 0 {
		document.Spec.Resources.Disk = formatMiB(cfg.RWLayerSizeMiB)
	}
	if cfg.KernelPolicy == config.KernelPolicyPinned || cfg.KernelPolicy == "" {
		document.Spec.Boot.Kernel = cfg.Kernel
	}
	if cfg.ImageRef != "" {
		document.Spec.Image = cfg.ImageRef
	} else {
		document.Spec.Image = cfg.Image
	}
	if cfg.LayerSet != nil {
		document.Spec.Root.LayerSet = &LayerSet{FSMeta: cfg.LayerSet.FSMeta, Layers: append([]string(nil), cfg.LayerSet.Layers...)}
	}
	parsedShares, err := shares.ParseSpecs(cfg.Shares)
	if err != nil {
		return Document{}, fmt.Errorf("export shares: %w", err)
	}
	for _, share := range parsedShares {
		document.Spec.Shares = append(document.Spec.Shares, Share{Name: share.Tag, Source: share.Path, Target: share.CtrPath, ReadOnly: share.RO, UID: share.UID, GID: share.GID})
	}
	for _, raw := range cfg.Ports {
		mapping, err := config.ParsePortSpec(raw)
		if err != nil {
			return Document{}, fmt.Errorf("export port %q: %w", raw, err)
		}
		document.Spec.Network.Ports = append(document.Spec.Network.Ports, Port{Host: net.JoinHostPort(mapping.HostIP, strconv.Itoa(int(mapping.HostPort))), Guest: mapping.GuestPort, Protocol: mapping.Proto})
	}
	if cfg.ProxyURL != "" || cfg.NoProxy != "" || cfg.ProxyEnforce {
		document.Spec.Network.Proxy = &Proxy{URL: cfg.ProxyURL, NoProxy: splitNonempty(cfg.NoProxy), Enforce: cfg.ProxyEnforce}
	}
	if cfg.OrgPolicy != nil {
		document.Spec.OrganizationPolicy = &OrganizationPolicy{Snapshot: &PolicySnapshot{BundleBase64: base64.StdEncoding.EncodeToString(cfg.OrgPolicy.Bundle), PublicKey: cfg.OrgPolicy.PublicKey, Profile: cfg.OrgPolicy.Profile}}
	}
	if cfg.OAuthBridge != nil || cfg.OAuthCustody != nil || len(cfg.OAuthProviders) != 0 {
		document.Spec.OAuth = &OAuth{Bridge: &bridge, Custody: custody}
		for _, provider := range cfg.OAuthProviders {
			document.Spec.OAuth.Providers = append(document.Spec.OAuth.Providers, providerFromSpec(provider))
		}
	}
	if cfg.MCP || len(cfg.MCPRemotes) != 0 {
		enabled := cfg.MCP
		document.Spec.MCP = &MCP{Enabled: &enabled, Filesystem: &MCPFS{Root: cfg.MCPFSRoot, User: cfg.MCPFSUser}}
		for _, raw := range cfg.MCPRemotes {
			remote, err := mcpspec.Parse(raw)
			if err != nil {
				return Document{}, fmt.Errorf("export MCP remote: %w", err)
			}
			document.Spec.MCP.Remotes = append(document.Spec.MCP.Remotes, remoteFromSpec(remote))
		}
	}
	secrets, err := exportSecrets(cfg)
	if err != nil {
		return Document{}, err
	}
	document.Spec.Secrets = secrets
	return document, nil
}

func exportSecrets(cfg config.RunConfig) ([]Secret, error) {
	sources := make(map[string]secret.Source, len(cfg.SecretSources))
	for _, named := range cfg.SecretSources {
		sources[named.Name] = named.Source
	}
	seen := make(map[string]bool)
	out := make([]Secret, 0, len(cfg.SecretNames))
	for _, persisted := range cfg.SecretNames {
		named, err := secret.ParseNamedSource(persisted)
		if err != nil {
			return nil, fmt.Errorf("export secret reference %q: %w", persisted, err)
		}
		if seen[named.Name] {
			continue
		}
		seen[named.Name] = true
		source, found := sources[named.Name]
		if !found {
			source = named.Source
		}
		entry := Secret{Name: named.Name, Bind: source.Binding}
		switch source.Kind {
		case secret.SourceFile:
			entry.File = source.Ref
			if source.Refresh > 0 {
				entry.TTL = source.Refresh.String()
			}
		case secret.SourceEnv, "":
			entry.Environment = named.Name
		default:
			// Exec sources are forbidden in current configurations. A legacy
			// value is exported as an explicit, redacted environment reference.
			entry.Environment = named.Name
		}
		out = append(out, entry)
	}
	return out, nil
}

func splitNonempty(value string) []string {
	var out []string
	for _, entry := range strings.Split(value, ",") {
		if trimmed := strings.TrimSpace(entry); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func intPointer(value int) *int { return &value }
