package sandbox

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/ejpir/gantry/internal/atomicfile"
	dashboardapi "github.com/ejpir/gantry/internal/dashboard/api"
	"github.com/ejpir/gantry/internal/guestasset"
	"github.com/ejpir/gantry/internal/netpol"
	"github.com/ejpir/gantry/internal/secret"
	"github.com/ejpir/gantry/internal/shares"
)

// NewDashboardService exposes sandbox control through the presentation-neutral
// dashboard contract. Constructing it performs no I/O.
func NewDashboardService() dashboardapi.Service { return dashboardService{} }

type dashboardService struct{}

var _ dashboardapi.Service = dashboardService{}

func (dashboardService) Snapshot() (dashboardapi.Snapshot, error) {
	return loadDashboardSnapshot()
}

func (dashboardService) Command(argv ...string) (*exec.Cmd, error) {
	executable, err := os.Executable()
	if err != nil {
		return nil, err
	}
	return exec.Command(executable, argv...), nil
}

func (dashboardService) ResourceLimits() dashboardapi.ResourceLimits {
	return dashboardapi.ResourceLimits{
		MinMemoryMB:        uint(minSandboxMemMB),
		MaxMemoryMB:        uint(maxSandboxMemMB),
		MinDiskSizeMiB:     minRWLayerSizeMiB,
		MaxDiskSizeMiB:     maxRWLayerSizeMiB,
		DefaultDiskSizeMiB: defaultRWLayerSizeMiB,
		MaxVCPUs:           maxSandboxVCPUs,
	}
}

func (dashboardService) KernelChoices() []string { return guestasset.KernelChoices() }

func (dashboardService) DefaultShareMount(tag string) string { return defaultHubCtrPath(tag) }

func (dashboardService) ValidateCreate(name string, memMB, diskSizeMiB uint, vcpus int, processIsolation string) error {
	if err := ValidateSandboxName(name); err != nil {
		return dashboardapi.Invalid("name", err)
	}
	if _, err := os.Stat(sandboxDir(name)); err == nil {
		return dashboardapi.Invalid("name", fmt.Errorf("sandbox %q already exists", name))
	}
	if err := validateSandboxResources(memMB, vcpus); err != nil {
		field := "memory"
		if strings.Contains(err.Error(), "CPU") || strings.Contains(err.Error(), "vCPU") {
			field = "cpu"
		}
		return dashboardapi.Invalid(field, err)
	}
	if err := validateRWLayerSize(diskSizeMiB); err != nil {
		return dashboardapi.Invalid("disk", err)
	}
	if err := validateProcessIsolation(processIsolation); err != nil {
		return dashboardapi.Invalid("isolation", err)
	}
	return nil
}

func (dashboardService) ValidateResources(memMB uint, vcpus int, processIsolation string) error {
	if err := validateSandboxResources(memMB, vcpus); err != nil {
		return err
	}
	return validateProcessIsolation(processIsolation)
}

func (dashboardService) SetResources(name string, memMB uint, vcpus int, processIsolation string) error {
	return setSandboxResources(name, memMB, vcpus, processIsolation)
}

func (dashboardService) ValidateNetworkPolicy(path string, allowLocal bool) error {
	_, _, err := resolveNetworkPolicy(path, allowLocal)
	return err
}

func (dashboardService) SetNetworkPolicy(name, path string, allowLocal bool) (dashboardapi.PolicyResult, error) {
	entry, err := setSandboxNetworkPolicy(name, path, allowLocal)
	return dashboardapi.PolicyResult{Path: entry.Path, Description: entry.Description}, err
}

func (dashboardService) ValidateNetworkRule(request dashboardapi.RuleRequest) error {
	_, err := normalizedDashboardRule(request)
	return err
}

func (dashboardService) AddNetworkRule(request dashboardapi.RuleRequest) error {
	spec, err := normalizedDashboardRule(request)
	if err != nil {
		return err
	}
	return mutateDashboardNetworkPolicy(request.Sandbox, func(policy *netpol.Policy) (*netpol.Policy, error) {
		return netpol.WithRule(policy, spec)
	})
}

func (dashboardService) RemoveNetworkRule(row dashboardapi.Rule) error {
	const prefix = "rule "
	switch {
	case strings.HasPrefix(row.Source, prefix):
		number, err := strconv.Atoi(strings.TrimPrefix(row.Source, prefix))
		if err != nil || number < 1 {
			return fmt.Errorf("invalid policy rule source %q", row.Source)
		}
		return mutateDashboardNetworkPolicy(row.Sandbox, func(policy *netpol.Policy) (*netpol.Policy, error) {
			return netpol.WithoutRule(policy, number-1)
		})
	case row.Source == "domain":
		return mutateDashboardNetworkPolicy(row.Sandbox, func(policy *netpol.Policy) (*netpol.Policy, error) {
			return netpol.WithoutDomain(policy, row.Target)
		})
	default:
		return fmt.Errorf("effective %s rows cannot be removed; edit the network policy instead", row.Source)
	}
}

func (dashboardService) RemoveTrafficRule(row dashboardapi.Traffic) error {
	request, err := dashboardRuleForTraffic(row, "allow")
	if err != nil {
		return err
	}
	spec, err := normalizedDashboardRule(request)
	if err != nil {
		return err
	}
	return mutateDashboardNetworkPolicy(row.Sandbox, func(policy *netpol.Policy) (*netpol.Policy, error) {
		return netpol.WithoutMatchingRule(policy, spec)
	})
}

func (dashboardService) ValidateSecret(request dashboardapi.SecretRequest) error {
	if err := ValidateSandboxName(request.Sandbox); err != nil {
		return dashboardapi.Invalid("sandbox", err)
	}
	if err := secret.ValidateName(strings.TrimSpace(request.Name)); err != nil {
		return dashboardapi.Invalid("name", err)
	}
	if request.Value == "" {
		return dashboardapi.Invalid("value", fmt.Errorf("secret value is required"))
	}
	if len(request.Value) > secretsHandshakeMaxBytes {
		return dashboardapi.Invalid("value", fmt.Errorf("secret value is too large"))
	}
	wireProbe := brokerRequest{
		Op: "secret.set", ID: strings.Repeat("x", 64),
		Secret: &brokerSecretRequest{Name: strings.TrimSpace(request.Name), Value: request.Value},
	}
	wire, err := json.Marshal(wireProbe)
	if err != nil || len(wire)+1 > controlMaxRequestBytes {
		return dashboardapi.Invalid("value", fmt.Errorf("secret value is too large for a live control request"))
	}
	if _, alive := sandboxPID(request.Sandbox); !alive {
		return dashboardapi.Invalid("sandbox", fmt.Errorf("start the sandbox before adding an in-memory secret"))
	}
	return nil
}

func (service dashboardService) AddSecret(request dashboardapi.SecretRequest) error {
	if err := service.ValidateSecret(request); err != nil {
		return err
	}
	return mutateSandboxSecret(request.Sandbox, "secret.set", strings.TrimSpace(request.Name), request.Value)
}

func (dashboardService) RemoveSecret(row dashboardapi.Secret) error {
	if err := ValidateSandboxName(row.Sandbox); err != nil {
		return err
	}
	if err := secret.ValidateName(row.Name); err != nil {
		return err
	}
	if _, alive := sandboxPID(row.Sandbox); alive {
		return mutateSandboxSecret(row.Sandbox, "secret.remove", row.Name, "")
	}
	store, err := LoadConfigStore(sandboxDir(row.Sandbox))
	if err != nil {
		return err
	}
	return store.SetSecretName(row.Name, false)
}

func mutateSandboxSecret(name, op, secretName string, value secret.Value) error {
	req := brokerRequest{Op: op, ID: newControlRequestID("secret"), Secret: &brokerSecretRequest{Name: secretName, Value: value}}
	resp, err := callControl[brokerSecretResponse](name, req)
	if err != nil {
		return err
	}
	if !resp.OK {
		if resp.Error == "" {
			resp.Error = "secret update failed"
		}
		return fmt.Errorf("%s", resp.Error)
	}
	return nil
}

func dashboardRuleForTraffic(row dashboardapi.Traffic, action string) (dashboardapi.RuleRequest, error) {
	proto := strings.ToLower(row.Protocol)
	if proto != "tcp" && proto != "udp" && proto != "icmp" {
		proto = "any"
	}
	if _, err := netip.ParseAddr(row.Address); err != nil {
		return dashboardapi.RuleRequest{}, fmt.Errorf("traffic destination %q is not an IP address", row.Address)
	}
	ports := ""
	if row.Port != 0 && (proto == "tcp" || proto == "udp") {
		ports = strconv.Itoa(int(row.Port))
	}
	return dashboardapi.RuleRequest{
		Sandbox: row.Sandbox, Action: action, Target: row.Address,
		Proto: proto, Ports: ports,
	}, nil
}

func normalizedDashboardRule(request dashboardapi.RuleRequest) (netpol.RuleSpec, error) {
	spec := netpol.RuleSpec{
		Action:   strings.ToLower(strings.TrimSpace(request.Action)),
		CIDR:     strings.TrimSpace(request.Target),
		Protocol: strings.ToLower(strings.TrimSpace(request.Proto)),
		Ports:    strings.TrimSpace(request.Ports),
	}
	if spec.CIDR != "" && !strings.Contains(spec.CIDR, "/") {
		address, err := netip.ParseAddr(spec.CIDR)
		if err != nil || !address.Is4() {
			return netpol.RuleSpec{}, dashboardapi.Invalid("target", fmt.Errorf("target must be an IPv4 address or CIDR"))
		}
		spec.CIDR = address.String() + "/32"
	}
	if _, err := netpol.WithRule(netpol.DefaultPolicy(), spec); err != nil {
		field := "ports"
		switch {
		case strings.Contains(err.Error(), "action"):
			field = "action"
		case strings.Contains(err.Error(), "protocol") || strings.Contains(err.Error(), "proto"):
			field = "protocol"
		case strings.Contains(err.Error(), "cidr"):
			field = "target"
		}
		return netpol.RuleSpec{}, dashboardapi.Invalid(field, err)
	}
	return spec, nil
}

func mutateDashboardNetworkPolicy(name string, mutate func(*netpol.Policy) (*netpol.Policy, error)) error {
	if err := ValidateSandboxName(name); err != nil {
		return err
	}
	cfg, err := readSandboxConfig(sandboxDir(name))
	if err != nil {
		return err
	}
	_, policy, err := resolveNetworkPolicy(cfg.NetPol, cfg.AllowLN)
	if err != nil {
		return err
	}
	next, err := mutate(policy)
	if err != nil {
		return err
	}
	data, err := netpol.Marshal(next)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(data)
	dir := filepath.Join(sandboxDir(name), "network-policies")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	path := filepath.Join(dir, fmt.Sprintf("%x.json", digest[:12]))
	if err := atomicfile.WriteFileDurable(path, append(data, '\n'), 0o600); err != nil {
		return err
	}
	_, err = setSandboxNetworkPolicy(name, path, cfg.AllowLN)
	return err
}

func (dashboardService) PlanShare(req dashboardapi.ShareRequest) (dashboardapi.SharePlan, error) {
	if req.Tag == "" {
		return dashboardapi.SharePlan{}, dashboardapi.Invalid("tag", fmt.Errorf("tag is required"))
	}
	if err := shares.ValidateShareTag(req.Tag); err != nil {
		return dashboardapi.SharePlan{}, dashboardapi.Invalid("tag", err)
	}
	if req.Path == "" {
		return dashboardapi.SharePlan{}, dashboardapi.Invalid("path", fmt.Errorf("host path is required"))
	}
	if req.Mountpoint != "" && !strings.HasPrefix(req.Mountpoint, "/") {
		return dashboardapi.SharePlan{}, dashboardapi.Invalid("mountpoint", fmt.Errorf("mount point must be an absolute path"))
	}

	defaultMount := shares.HubHostPath + "/" + req.Tag
	customMount := req.Mountpoint != "" && req.Mountpoint != defaultMount
	uid, gid, err := parseShareOwner(req.Owner)
	if err != nil {
		return dashboardapi.SharePlan{}, dashboardapi.Invalid("owner", err)
	}
	spec := shares.Spec{
		Tag: req.Tag, Path: req.Path, RO: req.ReadOnly, UID: uid, GID: gid,
	}
	if customMount {
		spec.CtrPath = req.Mountpoint
	}

	mountpoint := req.Mountpoint
	if mountpoint == "" {
		mountpoint = defaultMount
	}
	live := req.Running && !customMount
	if req.Replace && req.CurrentGuest != "" && req.CurrentGuest != defaultMount {
		live = false
	}
	return dashboardapi.SharePlan{
		Sandbox: req.Sandbox, Tag: req.Tag, Spec: spec.String(), Mountpoint: mountpoint,
		Replace: req.Replace, Live: live,
	}, nil
}

func (dashboardService) ConfigureShare(plan dashboardapi.SharePlan) error {
	return configureSandboxShare(plan.Sandbox, plan.Spec, plan.Replace)
}

func (dashboardService) RemoveShare(mount dashboardapi.Mount) error {
	return removeSandboxShare(mount.Sandbox, mount.Tag, dashboardShareRemovalNeedsForce(mount))
}

func dashboardShareRemovalNeedsForce(mount dashboardapi.Mount) bool {
	return mount.Guest != "" && mount.Guest != shares.HubHostPath+"/"+mount.Tag
}

func (dashboardService) PlanPort(req dashboardapi.PortRequest) (string, error) {
	guest := strings.TrimSpace(req.Guest)
	if _, err := parseDashboardPort(guest, "guest port"); err != nil {
		return "", dashboardapi.Invalid("guest", err)
	}
	bind := strings.TrimSpace(req.Bind)
	spec := guest
	if bind != "" {
		host, port := bind, ""
		if parsedHost, parsedPort, err := net.SplitHostPort(bind); err == nil {
			host, port = parsedHost, parsedPort
		}
		if port != "" {
			if addr, err := netip.ParseAddr(host); err != nil || addr.Zone() != "" {
				return "", dashboardapi.Invalid("bind", fmt.Errorf("host bind %q is not an IP address", host))
			}
			if _, err := parseDashboardPort(port, "host port"); err != nil {
				return "", dashboardapi.Invalid("bind", err)
			}
			spec = bind + ":" + guest
		} else {
			if _, err := parseDashboardPort(host, "host bind (want port or ip:port)"); err != nil {
				return "", dashboardapi.Invalid("bind", err)
			}
			spec = host + ":" + guest
		}
	}
	if req.UDP {
		spec += "/udp"
	}
	if _, err := ParsePortSpec(spec); err != nil {
		return "", dashboardapi.Invalid("bind", err)
	}
	return spec, nil
}

func parseDashboardPort(value, what string) (int, error) {
	if value == "" {
		return 0, fmt.Errorf("%s is required", what)
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("%s must be a number 1-65535 (got %q)", what, value)
		}
	}
	n, err := strconv.Atoi(value)
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("%s must be a number 1-65535 (got %q)", what, value)
	}
	return n, nil
}

func parseShareOwner(raw string) (*uint32, *uint32, error) {
	value := strings.TrimSpace(raw)
	if value == "" || value == "host" {
		return nil, nil, nil
	}
	uidText, gidText, ok := strings.Cut(value, ":")
	if !ok || uidText == "" || gidText == "" {
		return nil, nil, fmt.Errorf("guest owner must be host or UID:GID")
	}
	uid, err := strconv.ParseUint(uidText, 10, 32)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid guest UID %q", uidText)
	}
	gid, err := strconv.ParseUint(gidText, 10, 32)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid guest GID %q", gidText)
	}
	uid32, gid32 := uint32(uid), uint32(gid)
	return &uid32, &gid32, nil
}

func loadDashboardSnapshot() (dashboardapi.Snapshot, error) {
	entries, err := os.ReadDir(sandboxRoot())
	if os.IsNotExist(err) {
		return dashboardapi.Snapshot{}, nil
	}
	if err != nil {
		return dashboardapi.Snapshot{}, err
	}

	data := dashboardapi.Snapshot{Sandboxes: make([]dashboardapi.Sandbox, 0, len(entries))}
	for _, entry := range entries {
		if !entry.IsDir() || !validSandboxName(entry.Name()) {
			continue
		}
		name := entry.Name()
		dir := sandboxDir(name)
		sandbox := dashboardapi.Sandbox{
			Name: name, State: dashboardapi.Stopped, Image: "unknown", Runtime: "crun",
			Secrets: "none", MemMB: 512, VCPUs: 1, Dir: dir,
			ConfigPath: filepath.Join(dir, "sandbox.json"),
		}
		if pid, alive := sandboxPID(name); alive {
			sandbox.PID = pid
			sandbox.State = dashboardapi.Starting
			if dashboardFileExists(filepath.Join(dir, "ready")) {
				sandbox.State = dashboardapi.Running
			}
		}
		if info, statErr := os.Stat(sandbox.ConfigPath); statErr == nil {
			sandbox.Updated = info.ModTime()
		}

		var cfg RunConfig
		configOK := false
		if raw, readErr := os.ReadFile(sandbox.ConfigPath); readErr == nil && json.Unmarshal(raw, &cfg) == nil {
			configOK = true
			sandbox.Image = cfg.ImageRef
			if sandbox.Image == "" {
				sandbox.Image = filepath.Base(cfg.Image)
			}
			if sandbox.Image == "" {
				sandbox.Image = "unknown"
			}
			if cfg.Runtime != "" {
				sandbox.Runtime = cfg.Runtime
			}
			sandbox.RW, sandbox.Net, sandbox.Shares = cfg.RW, cfg.Net, len(cfg.Shares)
			sandbox.ProcessIsolation = normalizedProcessIsolation(cfg.ProcessIsolation)
			sandbox.GVProxy = cfg.GVProxy
			sandbox.NetPolicy = cfg.NetPol
			sandbox.AllowLocal = cfg.AllowLN
			if cfg.MemMB > 0 {
				sandbox.MemMB = cfg.MemMB
			}
			if cfg.VCPUs > 0 {
				sandbox.VCPUs = cfg.VCPUs
			}
			sandbox.SecretCount = len(cfg.SecretNames)
			if sandbox.SecretCount > 0 {
				sandbox.Secrets = strings.Join(cfg.SecretNames, ", ")
			}
		} else {
			sandbox.ConfigError = true
			data.Rules = append(data.Rules, dashboardapi.Rule{Sandbox: name, Action: "error", Target: "sandbox configuration unavailable", Proto: "—", Source: "sandbox.json", Error: true})
			data.Mounts = append(data.Mounts, dashboardapi.Mount{Sandbox: name, Tag: "invalid", Error: "sandbox configuration unavailable"})
		}

		trafficPath := filepath.Join(dir, netpol.TrafficFileName)
		sandbox.TrafficAvailable = dashboardFileExists(trafficPath)
		traffic, trafficErr := netpol.ReadTrafficSnapshot(trafficPath)
		if trafficErr == nil {
			sandbox.TXBytes, sandbox.RXBytes = traffic.TXBytes, traffic.RXBytes
			sandbox.DroppedPackets = traffic.DroppedPackets
			var classifiedDroppedBytes, classifiedDroppedPackets uint64
			for _, entry := range traffic.Entries {
				if !entry.Allowed {
					classifiedDroppedBytes += entry.TXBytes
					classifiedDroppedPackets += entry.TXPackets
				}
				data.Traffic = append(data.Traffic, dashboardapi.Traffic{
					Sandbox: name, Host: entry.Host, Address: entry.Address,
					Protocol: entry.Protocol, Port: entry.Port, Allowed: entry.Allowed,
					TXBytes: entry.TXBytes, RXBytes: entry.RXBytes,
					TXPackets: entry.TXPackets, RXPackets: entry.RXPackets,
					FirstSeen: entry.FirstSeen, LastSeen: entry.LastSeen,
				})
			}
			if traffic.DroppedPackets > classifiedDroppedPackets {
				data.Traffic = append(data.Traffic, dashboardapi.Traffic{
					Sandbox: name, Host: "unclassified traffic", Address: "non-IP / historical",
					Protocol: "other", Allowed: false,
					TXBytes:   traffic.DroppedBytes - dashboardMinUint64(traffic.DroppedBytes, classifiedDroppedBytes),
					TXPackets: traffic.DroppedPackets - classifiedDroppedPackets,
					LastSeen:  traffic.Updated,
				})
			}
		}
		if configOK {
			secretState := "required next start"
			if sandbox.State == dashboardapi.Running {
				secretState = "loaded"
			}
			for _, secretName := range cfg.SecretNames {
				data.Secrets = append(data.Secrets, dashboardapi.Secret{Sandbox: sandbox.Name, Name: secretName, State: secretState})
			}
			data.Rules = append(data.Rules, loadDashboardRules(name, cfg)...)
			mounts, live := loadDashboardMounts(name, cfg, sandbox.State == dashboardapi.Running)
			data.Mounts = append(data.Mounts, mounts...)
			if live {
				sandbox.Shares = len(mounts)
			}
			data.Ports = append(data.Ports, loadDashboardPorts(name, cfg, sandbox.State == dashboardapi.Running)...)
		}
		data.Sandboxes = append(data.Sandboxes, sandbox)
	}

	sort.Slice(data.Sandboxes, func(i, j int) bool {
		left, right := strings.ToLower(data.Sandboxes[i].Name), strings.ToLower(data.Sandboxes[j].Name)
		if left == right {
			return data.Sandboxes[i].Name < data.Sandboxes[j].Name
		}
		return left < right
	})
	sort.SliceStable(data.Traffic, func(i, j int) bool { return data.Traffic[i].LastSeen.After(data.Traffic[j].LastSeen) })
	sort.SliceStable(data.Rules, func(i, j int) bool { return data.Rules[i].Sandbox < data.Rules[j].Sandbox })
	sort.SliceStable(data.Mounts, func(i, j int) bool {
		if data.Mounts[i].Sandbox == data.Mounts[j].Sandbox {
			return data.Mounts[i].Tag < data.Mounts[j].Tag
		}
		return data.Mounts[i].Sandbox < data.Mounts[j].Sandbox
	})
	sort.SliceStable(data.Ports, func(i, j int) bool {
		if data.Ports[i].Sandbox == data.Ports[j].Sandbox {
			return data.Ports[i].Bind < data.Ports[j].Bind
		}
		return data.Ports[i].Sandbox < data.Ports[j].Sandbox
	})
	sort.SliceStable(data.Secrets, func(i, j int) bool {
		if data.Secrets[i].Sandbox == data.Secrets[j].Sandbox {
			return data.Secrets[i].Name < data.Secrets[j].Name
		}
		return data.Secrets[i].Sandbox < data.Secrets[j].Sandbox
	})
	return data, nil
}

func loadDashboardRules(sandbox string, cfg RunConfig) []dashboardapi.Rule {
	if !cfg.Net {
		return []dashboardapi.Rule{{Sandbox: sandbox, Action: "off", Target: "network disabled", Proto: "—", Source: "config"}}
	}
	if cfg.GVProxy != "" {
		return []dashboardapi.Rule{{Sandbox: sandbox, Action: "allow", Target: "all destinations", Proto: "any", Source: "external gvproxy", Policy: cfg.GVProxy}}
	}
	policy := netpol.DefaultPolicy()
	policyPath := "built-in default"
	if cfg.NetPol != "" {
		loaded, err := netpol.Load(cfg.NetPol)
		if err != nil {
			return []dashboardapi.Rule{{Sandbox: sandbox, Action: "error", Target: err.Error(), Proto: "—", Source: "policy", Policy: cfg.NetPol, Error: true}}
		}
		policy, policyPath = loaded, cfg.NetPol
	}
	if cfg.AllowLN {
		policy.AllowLocal = true
	}
	summaries := policy.RuleSummaries()
	rows := make([]dashboardapi.Rule, 0, len(summaries))
	for _, summary := range summaries {
		rows = append(rows, dashboardapi.Rule{
			Sandbox: sandbox, Action: summary.Action, Target: summary.Target,
			Proto: summary.Protocol, Ports: summary.Ports, Source: summary.Source,
			Policy: policyPath,
		})
	}
	return rows
}

func loadDashboardMounts(sandbox string, cfg RunConfig, running bool) ([]dashboardapi.Mount, bool) {
	parsed, parseErr := cfg.ParsedShares()
	rowForConfigured := func(share shares.Spec, state string) dashboardapi.Mount {
		return dashboardapi.Mount{
			Sandbox: sandbox, Tag: share.Tag, Host: share.Path,
			VM: shares.HubVMPath + "/" + share.Tag, Guest: configuredShareTarget(share),
			ReadOnly: share.RO, UID: share.UID, GID: share.GID, State: state,
		}
	}
	if running {
		if raw, err := os.ReadFile(filepath.Join(sandboxDir(sandbox), "shares.json")); err == nil {
			var manifest shares.Manifest
			if json.Unmarshal(raw, &manifest) == nil && manifest.Transport != nil {
				rows := make([]dashboardapi.Mount, 0, len(manifest.Shares))
				for _, entry := range manifest.Shares {
					row := dashboardapi.Mount{
						Sandbox: sandbox, Tag: entry.Tag, Host: entry.Path,
						VM: entry.VMPath, Guest: entry.CtrPath,
						ReadOnly: entry.RO, UID: entry.UID, GID: entry.GID,
						State: defaultShareState(entry.State),
					}
					if row.State == "error" {
						row.Error = "share backend error"
					}
					rows = append(rows, row)
				}
				if parseErr != nil {
					rows = append(rows, dashboardapi.Mount{Sandbox: sandbox, Tag: "invalid", Error: parseErr.Error()})
					return rows, true
				}
				liveByTag := make(map[string]int, len(rows))
				for i := range rows {
					liveByTag[rows[i].Tag] = i
				}
				for _, configured := range parsed {
					desired := rowForConfigured(configured, "restart")
					if index, ok := liveByTag[desired.Tag]; ok {
						if dashboardMountsEqual(rows[index], desired) {
							continue
						}
						if rows[index].State == "error" {
							desired.State, desired.Error = rows[index].State, rows[index].Error
						}
						rows[index] = desired
						continue
					}
					rows = append(rows, desired)
				}
				return rows, true
			}
		} else if !os.IsNotExist(err) {
			return []dashboardapi.Mount{{Sandbox: sandbox, Tag: "invalid", Error: err.Error()}}, true
		}
	}
	if parseErr != nil {
		return []dashboardapi.Mount{{Sandbox: sandbox, Tag: "invalid", Error: parseErr.Error()}}, false
	}
	rows := make([]dashboardapi.Mount, 0, len(parsed))
	for _, share := range parsed {
		rows = append(rows, rowForConfigured(share, "saved"))
	}
	return rows, false
}

func dashboardMountsEqual(a, b dashboardapi.Mount) bool {
	return a.Tag == b.Tag && a.Host == b.Host && a.Guest == b.Guest && a.ReadOnly == b.ReadOnly &&
		optionalDashboardUint32Equal(a.UID, b.UID) && optionalDashboardUint32Equal(a.GID, b.GID)
}

func optionalDashboardUint32Equal(a, b *uint32) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func loadDashboardPorts(sandbox string, cfg RunConfig, running bool) []dashboardapi.Port {
	rowFor := func(mapping PortMapping, state string) dashboardapi.Port {
		return dashboardapi.Port{
			Sandbox: sandbox, Bind: mapping.Local(), Guest: int(mapping.GuestPort),
			Proto: mapping.Proto, State: state,
		}
	}
	if running {
		resp, err := portControlRPC(sandbox, "port.list", brokerPortRequest{Persistent: true})
		if err != nil {
			return []dashboardapi.Port{{Sandbox: sandbox, Bind: "unavailable", Error: err.Error()}}
		}
		rows := make([]dashboardapi.Port, 0, len(resp.Ports))
		for _, entry := range resp.Ports {
			rows = append(rows, rowFor(entry.Mapping, entry.State))
		}
		return rows
	}
	rows := make([]dashboardapi.Port, 0, len(cfg.Ports))
	for _, spec := range cfg.Ports {
		mapping, err := ParsePortSpec(spec)
		if err != nil {
			rows = append(rows, dashboardapi.Port{Sandbox: sandbox, Bind: "invalid", Error: err.Error()})
			continue
		}
		rows = append(rows, rowFor(mapping, "saved"))
	}
	return rows
}

func dashboardFileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func dashboardMinUint64(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}
