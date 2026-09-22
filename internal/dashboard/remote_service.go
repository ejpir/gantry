package dashboard

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/ejpir/gantry/api/managerapi"
	dashboardapi "github.com/ejpir/gantry/internal/dashboard/api"
	"github.com/ejpir/gantry/internal/netpol"
	"github.com/ejpir/gantry/internal/packetcapture"
	"github.com/ejpir/gantry/internal/remote"
	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/lifecycle"
)

// remoteDashboardService implements the same presentation-neutral contract as
// the local dashboard service, but every read and mutation is authenticated to
// one explicit manager profile. It is intentionally short-lived; credentials
// are reloaded for every operation so rotation takes effect without restarting
// the TUI.
type remoteDashboardService struct {
	name    string
	limits  dashboardapi.ResourceLimits
	kernels []string
}

var _ dashboardapi.Service = remoteDashboardService{}

func (service remoteDashboardService) withClient(ctx context.Context, call func(*remote.Client) error) error {
	profile, token, err := remote.Load(service.name)
	if err != nil {
		return err
	}
	client, err := remote.Dial(profile, token)
	if err != nil {
		return err
	}
	defer client.Close()
	return call(client)
}

func (service remoteDashboardService) action(request dashboardapi.ActionRequest) (dashboardapi.ActionResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var result dashboardapi.ActionResult
	err := service.withClient(ctx, func(client *remote.Client) error {
		var err error
		result, err = client.DashboardAction(ctx, request)
		return err
	})
	var apiErr *remote.Error
	if errors.As(err, &apiErr) && (apiErr.Status == 404 || apiErr.Status == 501) {
		err = fmt.Errorf("remote %q does not provide dashboard control; upgrade and restart gantry serve", service.name)
	}
	return result, err
}

func (service remoteDashboardService) Snapshot() (dashboardapi.Snapshot, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var result dashboardapi.HostSnapshot
	err := service.withClient(ctx, func(client *remote.Client) error {
		var err error
		result, err = client.DashboardSnapshot(ctx)
		return err
	})
	return result.Snapshot, err
}

func (service remoteDashboardService) Start(ctx context.Context, request lifecycle.StartRequest, _ lifecycle.Observer) (lifecycle.StartResult, error) {
	if request.Mode != lifecycle.Resume {
		return lifecycle.StartResult{}, errors.New("remote dashboard service only resumes saved sandboxes")
	}
	err := service.withClient(ctx, func(client *remote.Client) error {
		_, err := client.StartSandbox(ctx, request.Name)
		return err
	})
	return lifecycle.StartResult{Name: request.Name}, err
}

func (service remoteDashboardService) Command(ctx context.Context, argv ...string) (*exec.Cmd, error) {
	executable, err := os.Executable()
	if err != nil {
		return nil, err
	}
	insert := len(argv)
	for index, arg := range argv {
		if arg == "--" {
			insert = index
			break
		}
		if arg == "-remote" || arg == "--remote" || strings.HasPrefix(arg, "-remote=") || strings.HasPrefix(arg, "--remote=") {
			return nil, errors.New("remote dashboard command already contains a target")
		}
	}
	routed := append([]string(nil), argv[:insert]...)
	routed = append(routed, "-remote", service.name)
	routed = append(routed, argv[insert:]...)
	command := exec.CommandContext(ctx, executable, routed...)
	command.Env = append(os.Environ(), "GANTRY_REMOTE=")
	command.WaitDelay = 2 * time.Second
	return command, nil
}

func (service remoteDashboardService) ResourceLimits() dashboardapi.ResourceLimits {
	return service.limits
}
func (service remoteDashboardService) KernelChoices() []string {
	return append([]string(nil), service.kernels...)
}
func (remoteDashboardService) DefaultShareMount(tag string) string {
	return config.DefaultHubCtrPath(tag)
}

func (service remoteDashboardService) ValidateCreate(name string, memMB, diskSizeMiB uint, vcpus int, isolation string) error {
	if err := remote.ValidateSandboxName(name); err != nil {
		return dashboardapi.Invalid("name", err)
	}
	if err := service.ValidateResources(memMB, vcpus, isolation); err != nil {
		return err
	}
	if err := config.ValidateRWLayerSize(diskSizeMiB); err != nil {
		return err
	}
	return nil
}

func (service remoteDashboardService) ValidateResources(memMB uint, vcpus int, isolation string) error {
	if err := config.ValidateSandboxResourceBounds(memMB, vcpus); err != nil {
		return err
	}
	if service.limits.MinMemoryMB > 0 && memMB < service.limits.MinMemoryMB {
		return fmt.Errorf("memory must be at least %d MiB", service.limits.MinMemoryMB)
	}
	if service.limits.MaxMemoryMB > 0 && memMB > service.limits.MaxMemoryMB {
		return fmt.Errorf("memory must be at most %d MiB", service.limits.MaxMemoryMB)
	}
	if service.limits.MaxVCPUs > 0 && vcpus > service.limits.MaxVCPUs {
		return fmt.Errorf("CPUs must be between 1 and %d", service.limits.MaxVCPUs)
	}
	return config.ValidateProcessIsolation(isolation)
}

func (service remoteDashboardService) SetResources(name string, memMB uint, vcpus int, isolation string) error {
	wire := managerapi.ConfigureSandboxRequest{MemoryMiB: &memMB, CPUs: &vcpus, ProcessIsolation: &isolation}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	return service.withClient(ctx, func(client *remote.Client) error {
		_, err := client.ConfigureSandbox(ctx, name, wire, "")
		return err
	})
}

func (service remoteDashboardService) ValidateSandboxConfig(request dashboardapi.SandboxConfigRequest) error {
	if request.DevContainers && !request.SSH {
		return dashboardapi.Invalid("devcontainers", errors.New("devcontainers requires SSH"))
	}
	return service.ValidateResources(request.MemMB, request.VCPUs, request.ProcessIsolation)
}

func (service remoteDashboardService) ConfigureSandbox(request dashboardapi.SandboxConfigRequest) (bool, error) {
	if err := service.ValidateSandboxConfig(request); err != nil {
		return false, err
	}
	wire := managerapi.ConfigureSandboxRequest{
		SSH: &request.SSH, DevContainers: &request.DevContainers,
		MemoryMiB: &request.MemMB, CPUs: &request.VCPUs, ProcessIsolation: &request.ProcessIsolation,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var restart bool
	err := service.withClient(ctx, func(client *remote.Client) error {
		operation, err := client.ConfigureSandbox(ctx, request.Name, wire, "")
		if err == nil && operation.Configure != nil {
			restart = operation.Configure.RestartRequired
		}
		return err
	})
	return restart, err
}

func (remoteDashboardService) ValidateNetworkPolicy(path string, _ bool) error {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	_, err := netpol.Load(path)
	return err
}

func (service remoteDashboardService) SetNetworkPolicy(name, path string, allowLocal bool) (dashboardapi.PolicyResult, error) {
	request := managerapi.NetworkPolicyRequest{AllowLocal: allowLocal}
	if path == "" {
		request.Default = true
	} else {
		data, err := os.ReadFile(path)
		if err != nil {
			return dashboardapi.PolicyResult{}, err
		}
		request.Policy = data
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	err := service.withClient(ctx, func(client *remote.Client) error {
		_, err := client.SetNetworkPolicy(ctx, name, request)
		return err
	})
	return dashboardapi.PolicyResult{Path: path, Description: "updated on remote " + service.name}, err
}

func (service remoteDashboardService) ValidateNetworkRule(request dashboardapi.RuleRequest) error {
	_, err := service.action(dashboardapi.ActionRequest{Action: "validate-rule", RuleRequest: &request})
	return err
}
func (service remoteDashboardService) AddNetworkRule(request dashboardapi.RuleRequest) error {
	_, err := service.action(dashboardapi.ActionRequest{Action: "add-rule", RuleRequest: &request})
	return err
}
func (service remoteDashboardService) RemoveNetworkRule(row dashboardapi.Rule) error {
	row.Remote = ""
	_, err := service.action(dashboardapi.ActionRequest{Action: "remove-rule", Rule: &row})
	return err
}
func (service remoteDashboardService) RemoveTrafficRule(row dashboardapi.Traffic) error {
	row.Remote = ""
	_, err := service.action(dashboardapi.ActionRequest{Action: "remove-traffic-rule", Traffic: &row})
	return err
}

func (service remoteDashboardService) ValidateSecret(request dashboardapi.SecretRequest) error {
	_, err := service.action(dashboardapi.ActionRequest{Action: "validate-secret", Secret: &request})
	return err
}
func (service remoteDashboardService) AddSecret(request dashboardapi.SecretRequest) error {
	_, err := service.action(dashboardapi.ActionRequest{Action: "add-secret", Secret: &request})
	return err
}
func (service remoteDashboardService) RemoveSecret(row dashboardapi.Secret) error {
	row.Remote = ""
	_, err := service.action(dashboardapi.ActionRequest{Action: "remove-secret", SecretRow: &row})
	return err
}

func (service remoteDashboardService) ValidateMCPRemote(request dashboardapi.MCPRemoteRequest) error {
	_, err := service.action(dashboardapi.ActionRequest{Action: "validate-mcp-remote", MCPRemote: &request})
	return err
}
func (service remoteDashboardService) ConfigureMCPRemote(request dashboardapi.MCPRemoteRequest) error {
	_, err := service.action(dashboardapi.ActionRequest{Action: "configure-mcp-remote", MCPRemote: &request})
	return err
}
func (service remoteDashboardService) ValidateMCPFilesystem(request dashboardapi.MCPFilesystemRequest) error {
	_, err := service.action(dashboardapi.ActionRequest{Action: "validate-mcp-filesystem", MCPFilesystem: &request})
	return err
}
func (service remoteDashboardService) ConfigureMCPFilesystem(request dashboardapi.MCPFilesystemRequest) error {
	_, err := service.action(dashboardapi.ActionRequest{Action: "configure-mcp-filesystem", MCPFilesystem: &request})
	return err
}
func (service remoteDashboardService) RemoveMCPRemote(row dashboardapi.MCPServer) error {
	row.Remote = ""
	_, err := service.action(dashboardapi.ActionRequest{Action: "remove-mcp-remote", MCPServer: &row})
	return err
}

func (service remoteDashboardService) RemoveImage(ref string) error {
	_, err := service.action(dashboardapi.ActionRequest{Action: "remove-image", Value: ref})
	return err
}
func (service remoteDashboardService) PruneImages() (int, error) {
	result, err := service.action(dashboardapi.ActionRequest{Action: "prune-images"})
	return result.Count, err
}
func (service remoteDashboardService) ValidateRegistryLogin(request dashboardapi.RegistryLoginRequest) error {
	_, err := service.action(dashboardapi.ActionRequest{Action: "validate-registry", Registry: &request})
	return err
}
func (service remoteDashboardService) StoreRegistryLogin(request dashboardapi.RegistryLoginRequest) (string, error) {
	result, err := service.action(dashboardapi.ActionRequest{Action: "store-registry", Registry: &request})
	return result.Warning, err
}
func (service remoteDashboardService) RemoveRegistryLogin(registry string) error {
	_, err := service.action(dashboardapi.ActionRequest{Action: "remove-registry", Value: registry})
	return err
}

func (service remoteDashboardService) PlanShare(request dashboardapi.ShareRequest) (dashboardapi.SharePlan, error) {
	result, err := service.action(dashboardapi.ActionRequest{Action: "plan-share", Share: &request})
	if err != nil {
		return dashboardapi.SharePlan{}, err
	}
	if result.SharePlan == nil {
		return dashboardapi.SharePlan{}, errors.New("remote manager returned no share plan")
	}
	return *result.SharePlan, nil
}
func (service remoteDashboardService) ConfigureShare(plan dashboardapi.SharePlan) error {
	_, err := service.action(dashboardapi.ActionRequest{Action: "configure-share", SharePlan: &plan})
	return err
}
func (service remoteDashboardService) RemoveShare(row dashboardapi.Mount) error {
	row.Remote = ""
	_, err := service.action(dashboardapi.ActionRequest{Action: "remove-share", Mount: &row})
	return err
}
func (service remoteDashboardService) PlanPort(request dashboardapi.PortRequest) (string, error) {
	result, err := service.action(dashboardapi.ActionRequest{Action: "plan-port", PortRequest: &request})
	return result.PortSpec, err
}
func (service remoteDashboardService) PublishPort(name, spec string) error {
	_, err := service.action(dashboardapi.ActionRequest{Action: "publish-port", Port: &dashboardapi.PortMutationRequest{Sandbox: name, Spec: spec}})
	return err
}
func (service remoteDashboardService) UnpublishPort(name, spec string) error {
	_, err := service.action(dashboardapi.ActionRequest{Action: "unpublish-port", Port: &dashboardapi.PortMutationRequest{Sandbox: name, Spec: spec}})
	return err
}
func (service remoteDashboardService) CapturePackets(name string, request packetcapture.Request) (packetcapture.Snapshot, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var snapshot packetcapture.Snapshot
	err := service.withClient(ctx, func(client *remote.Client) error {
		var err error
		snapshot, err = client.CapturePackets(ctx, name, request)
		return err
	})
	return snapshot, err
}

func (m sandboxTUIModel) serviceForRemote(name string) dashboardapi.Service {
	if name == "" {
		return m.service
	}
	service := remoteDashboardService{name: name, limits: m.limits}
	if section, ok := m.remotes[name]; ok && section.Dashboard != nil {
		service.limits = section.Dashboard.ResourceLimits
		service.kernels = section.Dashboard.KernelChoices
	}
	return service
}

func remoteOperationLabel(name, source string) string {
	if source == "" {
		return name
	}
	return fmt.Sprintf("%s@%s", name, source)
}
