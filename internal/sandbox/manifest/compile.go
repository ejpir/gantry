package manifest

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ejpir/gantry/internal/client"
	"github.com/ejpir/gantry/internal/mcpspec"
	"github.com/ejpir/gantry/internal/oauthprovider"
	"github.com/ejpir/gantry/internal/policy"
	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/layout"
	"github.com/ejpir/gantry/internal/secret"
	"github.com/ejpir/gantry/internal/shares"
	"go.yaml.in/yaml/v3"
)

// Compile validates and normalizes document into the shared launch model.
func Compile(document Document, baseDir string) (Compiled, error) {
	if document.APIVersion != APIVersion {
		return Compiled{}, fmt.Errorf("apiVersion must be %q", APIVersion)
	}
	if document.Kind != Kind {
		return Compiled{}, fmt.Errorf("kind must be %q", Kind)
	}
	if err := layout.ValidateName(document.Metadata.Name); err != nil {
		return Compiled{}, fmt.Errorf("metadata.name: %w", err)
	}
	if baseDir == "" {
		baseDir = "."
	}
	baseDir, _ = filepath.Abs(baseDir)
	options := config.DefaultRunOptions()
	options.Name = document.Metadata.Name
	options.Image = resolveImagePath(baseDir, document.Spec.Image)
	document.Spec.Image = options.Image
	if document.Spec.Runtime != "" {
		options.Runtime = document.Spec.Runtime
	}
	if options.Runtime != "crun" && options.Runtime != "runsc" {
		return Compiled{}, fmt.Errorf("spec.runtime must be crun or runsc, got %q", options.Runtime)
	}
	if resources := document.Spec.Resources; resources != nil {
		if resources.CPUs != nil {
			options.VCPUs = *resources.CPUs
			options.Explicit.CPUs = true
		}
		var err error
		if resources.Memory != "" {
			options.MemMB, err = parseMiB(resources.Memory)
			if err != nil {
				return Compiled{}, fmt.Errorf("spec.resources.memory: %w", err)
			}
			options.Explicit.Memory = true
		}
		if resources.Disk != "" {
			options.RWLayerSizeMiB, err = parseMiB(resources.Disk)
			if err != nil {
				return Compiled{}, fmt.Errorf("spec.resources.disk: %w", err)
			}
			options.Explicit.DiskSize = true
		}
	}
	if err := config.ValidateSandboxResources(options.MemMB, options.VCPUs); err != nil {
		return Compiled{}, fmt.Errorf("spec.resources: %w", err)
	}
	if err := config.ValidateRWLayerSize(options.RWLayerSizeMiB); err != nil {
		return Compiled{}, fmt.Errorf("spec.resources.disk: %w", err)
	}
	if root := document.Spec.Root; root != nil {
		if root.Writable != nil {
			options.RW = *root.Writable
			options.Explicit.RW = true
		}
		root.Layer = resolveHostPath(baseDir, root.Layer)
		root.LayerSetFile = resolveHostPath(baseDir, root.LayerSetFile)
		options.RWLayer, options.LayerSet = root.Layer, root.LayerSetFile
		if root.LayerSet != nil {
			if root.LayerSetFile != "" {
				return Compiled{}, errors.New("spec.root.layerSet and layerSetFile are mutually exclusive")
			}
			root.LayerSet.FSMeta = resolveHostPath(baseDir, root.LayerSet.FSMeta)
			for index := range root.LayerSet.Layers {
				root.LayerSet.Layers[index] = resolveHostPath(baseDir, root.LayerSet.Layers[index])
			}
			if root.LayerSet.FSMeta == "" || len(root.LayerSet.Layers) == 0 {
				return Compiled{}, errors.New("spec.root.layerSet needs fsmeta and at least one layer")
			}
			options.LayerSetConfig = &client.LayerSet{FSMeta: root.LayerSet.FSMeta, Layers: append([]string(nil), root.LayerSet.Layers...)}
		}
	}
	if boot := document.Spec.Boot; boot != nil {
		boot.Kernel, boot.Rootfs = resolveHostPath(baseDir, boot.Kernel), resolveHostPath(baseDir, boot.Rootfs)
		if boot.Kernel != "" {
			options.Kernel, options.Explicit.Kernel = boot.Kernel, true
		}
		if boot.Rootfs != "" {
			options.Rootfs, options.Explicit.Rootfs = boot.Rootfs, true
		}
	}
	for index := range document.Spec.Shares {
		entry := &document.Spec.Shares[index]
		entry.Source = resolveHostPath(baseDir, entry.Source)
		spec := shares.Spec{Tag: entry.Name, Path: entry.Source, CtrPath: entry.Target, RO: entry.ReadOnly, UID: entry.UID, GID: entry.GID}
		options.Shares = append(options.Shares, spec.String())
	}
	if _, err := shares.ParseSpecs(options.Shares); err != nil {
		return Compiled{}, fmt.Errorf("spec.shares: %w", err)
	}
	if options.Explicit.RW && !options.RW && len(options.Shares) != 0 {
		return Compiled{}, errors.New("spec.shares require spec.root.writable to be true")
	}
	if network := document.Spec.Network; network != nil {
		if network.Enabled != nil {
			options.Net = *network.Enabled
		}
		options.AllowLN = network.AllowLocal
		network.Policy = resolveHostPath(baseDir, network.Policy)
		options.NetPol = network.Policy
		seenPorts := make(map[string]bool, len(network.Ports))
		for index, port := range network.Ports {
			raw, err := portSpec(port)
			if err != nil {
				return Compiled{}, fmt.Errorf("spec.network.ports[%d]: %w", index, err)
			}
			mapping, err := config.ParsePortSpec(raw)
			if err != nil {
				return Compiled{}, fmt.Errorf("spec.network.ports[%d]: %w", index, err)
			}
			if port.Host != "" {
				raw = mapping.String()
				if seenPorts[mapping.Key()] {
					return Compiled{}, fmt.Errorf("spec.network.ports[%d]: duplicate host binding %s", index, mapping.Local())
				}
				seenPorts[mapping.Key()] = true
			}
			options.Publish = append(options.Publish, raw)
		}
		if !options.Net && len(options.Publish) != 0 {
			return Compiled{}, errors.New("spec.network.ports require networking to be enabled")
		}
		if network.Proxy != nil {
			options.ProxyURL = network.Proxy.URL
			options.NoProxy = strings.Join(network.Proxy.NoProxy, ",")
			options.ProxyEnforce = network.Proxy.Enforce
		}
	}
	parsedProxy, err := config.ParseForwardProxy(options.ProxyURL)
	if err != nil {
		return Compiled{}, fmt.Errorf("spec.network.proxy: %w", err)
	}
	if err := config.ValidateProxyConfig(config.RunConfig{Net: options.Net, ProxyURL: parsedProxy.URL, NoProxy: options.NoProxy, ProxyEnforce: options.ProxyEnforce}); err != nil {
		return Compiled{}, fmt.Errorf("spec.network.proxy: %w", err)
	}
	seenSecrets := make(map[string]bool, len(document.Spec.Secrets))
	for index := range document.Spec.Secrets {
		entry := &document.Spec.Secrets[index]
		raw, err := secretSpec(baseDir, entry)
		if err != nil {
			return Compiled{}, fmt.Errorf("spec.secrets[%d]: %w", index, err)
		}
		if seenSecrets[entry.Name] {
			return Compiled{}, fmt.Errorf("spec.secrets[%d]: duplicate secret name %q", index, entry.Name)
		}
		seenSecrets[entry.Name] = true
		options.Secrets = append(options.Secrets, raw)
	}
	if organization := document.Spec.OrganizationPolicy; organization != nil {
		if organization.Snapshot != nil {
			if organization.Bundle != "" || organization.PublicKey != "" || organization.Profile != "" {
				return Compiled{}, errors.New("spec.organizationPolicy snapshot and file fields are mutually exclusive")
			}
			bundle, err := base64.StdEncoding.DecodeString(organization.Snapshot.BundleBase64)
			if err != nil {
				return Compiled{}, fmt.Errorf("spec.organizationPolicy.snapshot.bundleBase64: %w", err)
			}
			options.OrganizationSnapshot = &policy.Config{Bundle: bundle, PublicKey: organization.Snapshot.PublicKey, Profile: organization.Snapshot.Profile}
		} else {
			organization.Bundle = resolveHostPath(baseDir, organization.Bundle)
			organization.PublicKey = resolveHostPath(baseDir, organization.PublicKey)
			options.OrgPolicy, options.OrgPolicyKey, options.PolicyProfile = organization.Bundle, organization.PublicKey, organization.Profile
			if (options.OrgPolicy == "") != (options.OrgPolicyKey == "") || (options.OrgPolicy == "") != (options.PolicyProfile == "") {
				return Compiled{}, errors.New("spec.organizationPolicy requires bundle, publicKey, and profile together")
			}
		}
	}
	if oauth := document.Spec.OAuth; oauth != nil {
		if oauth.Bridge != nil {
			options.OAuthBridge = *oauth.Bridge
		}
		options.OAuthCustody = oauth.Custody
		for index := range oauth.ProviderFiles {
			oauth.ProviderFiles[index] = resolveHostPath(baseDir, oauth.ProviderFiles[index])
		}
		options.OAuthProviderFiles = append([]string(nil), oauth.ProviderFiles...)
		seenProviders := make(map[string]bool, len(oauth.Providers))
		for index, provider := range oauth.Providers {
			normalized, err := oauthprovider.Normalize(provider.spec())
			if err != nil {
				return Compiled{}, fmt.Errorf("spec.oauth.providers[%d]: %w", index, err)
			}
			if seenProviders[normalized.Provider] {
				return Compiled{}, fmt.Errorf("spec.oauth.providers[%d]: duplicate provider name %q", index, normalized.Provider)
			}
			seenProviders[normalized.Provider] = true
			options.OAuthProviders = append(options.OAuthProviders, normalized)
		}
		if len(options.OAuthProviderFiles)+len(options.OAuthProviders) > oauthprovider.MaxProviders {
			return Compiled{}, fmt.Errorf("spec.oauth has too many providers (max %d)", oauthprovider.MaxProviders)
		}
		if options.OAuthCustody && !options.OAuthBridge {
			return Compiled{}, errors.New("spec.oauth.custody requires bridge to be enabled")
		}
	}
	if mcp := document.Spec.MCP; mcp != nil {
		if mcp.Enabled != nil {
			options.MCP = *mcp.Enabled
		}
		if mcp.Filesystem != nil {
			if mcp.Filesystem.Root != "" {
				options.MCPFSRoot = mcp.Filesystem.Root
			}
			if mcp.Filesystem.User != "" {
				options.MCPFSUser = mcp.Filesystem.User
			}
		}
		seenRemotes := make(map[string]bool, len(mcp.Remotes))
		for index, remote := range mcp.Remotes {
			encoded, err := remote.encode()
			if err != nil {
				return Compiled{}, fmt.Errorf("spec.mcp.remotes[%d]: %w", index, err)
			}
			if seenRemotes[remote.Name] {
				return Compiled{}, fmt.Errorf("spec.mcp.remotes[%d]: duplicate server name %q", index, remote.Name)
			}
			seenRemotes[remote.Name] = true
			options.MCPRemotes = append(options.MCPRemotes, encoded)
		}
		if len(mcp.Remotes) > mcpspec.MaxRemotes {
			return Compiled{}, fmt.Errorf("spec.mcp has too many remotes (max %d)", mcpspec.MaxRemotes)
		}
		if len(mcp.Remotes) != 0 {
			options.MCP = true
		}
		root, user, err := config.NormalizeMCPFilesystem(options.MCPFSRoot, options.MCPFSUser)
		if err != nil {
			return Compiled{}, fmt.Errorf("spec.mcp.filesystem: %w", err)
		}
		options.MCPFSRoot, options.MCPFSUser = root, user
	}
	if document.Spec.SSH != nil {
		options.SSH = document.Spec.SSH.Enabled
	}
	if document.Spec.DevContainers != nil {
		options.DevContainers = document.Spec.DevContainers.Enabled
	}
	if options.DevContainers && !options.SSH {
		return Compiled{}, errors.New("spec.devContainers.enabled requires spec.ssh.enabled")
	}
	if options.DevContainers && options.Runtime != "crun" {
		return Compiled{}, errors.New("spec.devContainers.enabled requires spec.runtime crun")
	}
	if document.Spec.ProcessIsolation != "" {
		options.ProcessIsolation = document.Spec.ProcessIsolation
	}
	if err := config.ValidateProcessIsolation(options.ProcessIsolation); err != nil {
		return Compiled{}, fmt.Errorf("spec.processIsolation: %w", err)
	}
	canonical, err := yaml.Marshal(document)
	if err != nil {
		return Compiled{}, err
	}
	digest := sha256.Sum256(canonical)
	options.Manifest = &config.ManifestProvenance{APIVersion: APIVersion, Digest: fmt.Sprintf("sha256:%x", digest[:])}
	return Compiled{Document: document, Options: options}, nil
}

func resolveHostPath(baseDir, value string) string {
	if value == "" {
		return ""
	}
	if filepath.IsAbs(value) {
		return filepath.Clean(value)
	}
	return filepath.Clean(filepath.Join(baseDir, value))
}

func resolveImagePath(baseDir, value string) string {
	localPrefix := strings.HasPrefix(value, "./") || strings.HasPrefix(value, "../") ||
		strings.HasPrefix(value, `.\`) || strings.HasPrefix(value, `..\`)
	if value == "" || (!filepath.IsAbs(value) && !localPrefix) {
		return value
	}
	return resolveHostPath(baseDir, value)
}

func parseMiB(value string) (uint, error) {
	units := []struct {
		suffix string
		factor uint64
	}{{"TiB", 1 << 20}, {"GiB", 1 << 10}, {"MiB", 1}}
	for _, unit := range units {
		if !strings.HasSuffix(value, unit.suffix) {
			continue
		}
		number := strings.TrimSuffix(value, unit.suffix)
		parsed, err := strconv.ParseUint(number, 10, 64)
		if err != nil || parsed == 0 || parsed > uint64(^uint(0))/unit.factor {
			return 0, fmt.Errorf("invalid size %q", value)
		}
		return uint(parsed * unit.factor), nil
	}
	return 0, fmt.Errorf("size %q must be a whole number of MiB, GiB, or TiB", value)
}

func formatMiB(value uint) string {
	if value != 0 && value%1024 == 0 {
		return fmt.Sprintf("%dGiB", value/1024)
	}
	return fmt.Sprintf("%dMiB", value)
}

func portSpec(port Port) (string, error) {
	if port.Guest == 0 {
		return "", errors.New("guest must be between 1 and 65535")
	}
	protocol := strings.ToLower(port.Protocol)
	if protocol == "" {
		protocol = "tcp"
	}
	if protocol != "tcp" && protocol != "udp" {
		return "", fmt.Errorf("protocol must be tcp or udp, got %q", port.Protocol)
	}
	guest := strconv.Itoa(int(port.Guest))
	raw := guest
	if port.Host != "" {
		if _, err := strconv.ParseUint(port.Host, 10, 16); err == nil {
			raw = port.Host + ":" + guest
		} else {
			host, hostPort, err := net.SplitHostPort(port.Host)
			if err != nil || host == "" || hostPort == "" {
				return "", fmt.Errorf("host must be PORT or IP:PORT, got %q", port.Host)
			}
			raw = net.JoinHostPort(host, hostPort) + ":" + guest
		}
	}
	if protocol == "udp" {
		raw += "/udp"
	}
	return raw, nil
}

func secretSpec(baseDir string, entry *Secret) (string, error) {
	if err := secret.ValidateName(entry.Name); err != nil {
		return "", err
	}
	if (entry.Environment == "") == (entry.File == "") {
		return "", errors.New("exactly one of environment or file is required")
	}
	if entry.Environment != "" && entry.Environment != entry.Name {
		return "", fmt.Errorf("environment must match name %q; Gantry does not perform implicit secret renaming", entry.Name)
	}
	name := entry.Name
	if entry.Bind != "" {
		name += "@" + entry.Bind
	}
	if entry.File != "" {
		entry.File = resolveHostPath(baseDir, entry.File)
		name += "=@" + entry.File
	}
	if entry.TTL != "" {
		if entry.Environment != "" {
			return "", errors.New("ttl is only supported for file-backed secrets")
		}
		duration, err := time.ParseDuration(entry.TTL)
		if err != nil || duration < 0 {
			return "", fmt.Errorf("invalid ttl %q", entry.TTL)
		}
		name += ",ttl=" + duration.String()
	}
	if _, err := secret.ParseNamedSource(name); err != nil {
		return "", err
	}
	return name, nil
}

func (provider OAuthProvider) spec() oauthprovider.Spec {
	return oauthprovider.Spec{
		Provider: provider.Name, Grant: provider.Grant, AuthorizeURL: provider.AuthorizeURL,
		DeviceAuthorizationURL: provider.DeviceAuthorizationURL, TokenURL: provider.TokenURL,
		ClientID: provider.ClientID, RedirectURI: provider.RedirectURI, Scope: provider.Scope,
		Resource: provider.Resource, ExchangeEncoding: provider.ExchangeEncoding,
		RefreshEncoding: provider.RefreshEncoding, CredentialHosts: append([]string(nil), provider.CredentialHosts...),
	}
}

func (remote MCPRemote) encode() (string, error) {
	typed := mcpspec.Remote{Name: remote.Name, URL: remote.URL, Allow: append([]string(nil), remote.Allow...), Deny: append([]string(nil), remote.Deny...), RedactNames: append([]string(nil), remote.Redact...)}
	if remote.Auth != nil {
		typed.AuthKind, typed.AuthRef, typed.AuthHeader = remote.Auth.Type, remote.Auth.Reference, remote.Auth.Header
	}
	return mcpspec.Encode(typed)
}
