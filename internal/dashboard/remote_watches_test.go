package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
	"github.com/ejpir/gantry/api/managerapi"
	dashboardapi "github.com/ejpir/gantry/internal/dashboard/api"
	"github.com/ejpir/gantry/internal/remote"
	"github.com/ejpir/gantry/internal/sandbox/dashboardsvc"
)

type remoteActionRecordingService struct {
	dashboardapi.Service
	argv []string
}

func (s *remoteActionRecordingService) Command(ctx context.Context, argv ...string) (*exec.Cmd, error) {
	s.argv = append([]string(nil), argv...)
	return exec.CommandContext(ctx, "true"), nil
}

func TestUnifiedRemoteActionCarriesExplicitProfile(t *testing.T) {
	service := &remoteActionRecordingService{Service: dashboardsvc.NewDashboardService()}
	m := newSandboxTUIModel(service)
	t.Cleanup(m.operations.close)
	m.loading = false
	m.sandboxes = []tuiSandbox{
		{Name: "same", State: tuiStopped},
		{Name: "same", Remote: "team", State: tuiStopped},
	}
	m.cursor = 1
	_, cmd := m.primaryAction()
	if cmd == nil || strings.Join(service.argv, " ") != "resume same -remote team" || m.tuiOperationState.Name() != "same@team" {
		t.Fatalf("remote start routing: argv=%q operation=%q cmd=%v", service.argv, m.tuiOperationState.Name(), cmd)
	}
	var picker sandboxPicker
	if !picker.ResetWhereSource(m.sandboxes, "same", "team", func(tuiSandbox) bool { return true }) || len(picker.options) != 2 || picker.Remote() != "team" {
		t.Fatalf("source-scoped mutation picker lost remote identity: %#v", picker.options)
	}
}

func TestUnifiedRunningRemoteOpensInteractiveSSH(t *testing.T) {
	service := &remoteActionRecordingService{Service: dashboardsvc.NewDashboardService()}
	m := newSandboxTUIModel(service)
	t.Cleanup(m.operations.close)
	m.loading = false
	m.sandboxes = []tuiSandbox{{Name: "dev", Remote: "team", State: tuiRunning, SSH: true}}
	_, cmd := m.primaryAction()
	if cmd == nil || strings.Join(service.argv, " ") != "ssh dev -remote team" || m.tuiOperationState.Name() != "dev@team" {
		t.Fatalf("remote open routing: argv=%q operation=%q cmd=%v", service.argv, m.tuiOperationState.Name(), cmd)
	}
}

func TestRemoteOpenEnablesSSHThenChainsInteractiveSession(t *testing.T) {
	service := &remoteActionRecordingService{Service: dashboardsvc.NewDashboardService()}
	m := newSandboxTUIModel(service)
	t.Cleanup(m.operations.close)
	target := tuiSandbox{Name: "dev", Remote: "team", State: tuiRunning}
	m.pendingRemoteOpen = &target
	owner, ok := m.tuiOperationState.Begin("enable remote SSH", "dev@team", false)
	if !ok {
		t.Fatal("could not begin enable operation")
	}
	_, cmd := m.handleProcessDone(tuiProcessDoneMsg{owner: owner, action: "enable remote SSH", name: "dev@team"})
	if cmd == nil || strings.Join(service.argv, " ") != "ssh dev -remote team" || m.tuiOperationState.Action() != "open" {
		t.Fatalf("SSH chain: argv=%q action=%q cmd=%v", service.argv, m.tuiOperationState.Action(), cmd)
	}
}

func TestRemoteDashboardSnapshotUnifiesEveryResourceWithSource(t *testing.T) {
	m, _ := onboardingModel(t)
	m.sandboxes = []tuiSandbox{{Name: "same", State: tuiRunning}}
	m.rememberViewSource()
	host := dashboardapi.HostSnapshot{Snapshot: dashboardapi.Snapshot{
		Sandboxes:  []dashboardapi.Sandbox{{Name: "same", State: dashboardapi.Running, Net: true, SSH: true}},
		Traffic:    []dashboardapi.Traffic{{Sandbox: "same", Host: "example.test"}},
		Rules:      []dashboardapi.Rule{{Sandbox: "same", Source: "default"}},
		Mounts:     []dashboardapi.Mount{{Sandbox: "same", Tag: "code"}},
		Ports:      []dashboardapi.Port{{Sandbox: "same", Bind: "127.0.0.1:8080"}},
		Secrets:    []dashboardapi.Secret{{Sandbox: "same", Name: "TOKEN"}},
		MCPServers: []dashboardapi.MCPServer{{Sandbox: "same", Name: "fs"}},
		Audit:      []dashboardapi.AuditEvent{{Sandbox: "same", Line: "event"}},
		Images:     []dashboardapi.Image{{Ref: "remote:latest"}},
		Registries: []dashboardapi.RegistryAuth{{Registry: "example.test"}},
	}}
	_, _ = m.Update(remoteSectionMsg{snapshot: remote.WatchSnapshot{Remote: "team", Dashboard: &host}, generation: 1})
	if len(m.sandboxes) != 2 || m.sandboxes[1].Remote != "team" || !m.sandboxes[1].SSH || !m.sandboxes[1].Net {
		t.Fatalf("sandboxes = %#v", m.sandboxes)
	}
	for name, ok := range map[string]bool{
		"traffic":    len(m.traffic) == 1 && m.traffic[0].Remote == "team",
		"rules":      len(m.rules) == 1 && m.rules[0].Remote == "team",
		"mounts":     len(m.mounts) == 1 && m.mounts[0].Remote == "team",
		"ports":      len(m.ports) == 1 && m.ports[0].Remote == "team",
		"secrets":    len(m.secrets) == 1 && m.secrets[0].Remote == "team",
		"mcp":        len(m.mcpServers) == 1 && m.mcpServers[0].Remote == "team",
		"audit":      len(m.auditEvents) == 1 && m.auditEvents[0].Remote == "team",
		"images":     len(m.images) == 1 && m.images[0].Remote == "team",
		"registries": len(m.registries) == 1 && m.registries[0].Remote == "team",
	} {
		if !ok {
			t.Errorf("remote %s rows were not source-scoped", name)
		}
	}
}

func TestRemoteInventoryAppearsInOverviewWithSourceTag(t *testing.T) {
	m, _ := onboardingModel(t)
	m.width, m.height = 120, 35
	m.page = tuiOverviewPage
	m.sandboxes = []tuiSandbox{{Name: "same", State: tuiRunning, Image: "local:latest", VCPUs: 2, MemMB: 512}}
	m.rememberViewSource()

	_, _ = m.Update(remoteSectionMsg{snapshot: remote.WatchSnapshot{Remote: "team", Sandboxes: []managerapi.Sandbox{{
		Name: "same", State: "running", Image: "remote:latest", CPUs: 4, MemoryMiB: 2048, Writable: true,
	}}}, generation: 1})
	if len(m.sandboxes) != 2 || m.sandboxes[0].Remote != "" || m.sandboxes[1].Remote != "team" {
		t.Fatalf("unified inventory = %#v", m.sandboxes)
	}
	plain := ansi.Strip(m.View().Content)
	if !strings.Contains(plain, "same  [remote:team]") || !strings.Contains(plain, "remote:latest") {
		t.Fatalf("remote source tag missing from Overview:\n%s", plain)
	}

	m.cursor = 1
	_, _ = m.Update(remoteSectionMsg{snapshot: remote.WatchSnapshot{Remote: "team", Sandboxes: []managerapi.Sandbox{{
		Name: "same", State: "stopped", Image: "remote:latest", CPUs: 4, MemoryMiB: 2048,
	}}}, generation: 1})
	if selected := m.selected(); selected == nil || selected.Remote != "team" || selected.State != tuiStopped {
		t.Fatalf("same-name remote selection was not preserved: %#v", selected)
	}
}

func TestRemoteWatchesAdoptAddAndRemoveWithoutDashboardRestart(t *testing.T) {
	m, _ := onboardingModel(t)
	m.sandboxes = []tuiSandbox{{Name: "local-dev", State: tuiRunning}}
	m.rememberViewSource()
	profile := onboardingManager(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/events":
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = fmt.Fprint(w, ": ready\n\n")
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		case "/v1/sandboxes":
			_ = json.NewEncoder(w).Encode(map[string]any{"sandboxes": []managerapi.Sandbox{{Name: "remote-dev", State: "running"}}})
		case "/v1/dashboard":
			http.NotFound(w, r)
		default:
			t.Errorf("unexpected watch endpoint %s", r.URL.Path)
		}
	})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	events := make(chan tea.Msg, 32)
	stop := startRemoteWatches(ctx, func(msg tea.Msg) {
		select {
		case events <- msg:
		case <-ctx.Done():
		}
	})
	defer stop()
	if err := remote.Add(profile, onboardTestToken); err != nil {
		t.Fatal(err)
	}
	wait := func(removed bool) {
		t.Helper()
		timer := time.NewTimer(7 * time.Second)
		defer timer.Stop()
		for {
			select {
			case event := <-events:
				m.Update(event)
				if msg, ok := event.(remoteSectionMsg); ok && msg.snapshot.Remote == profile.Name && (removed && msg.removed || !removed && len(msg.snapshot.Sandboxes) == 1) {
					return
				}
			case <-timer.C:
				t.Fatal("dashboard did not adopt profile change")
			}
		}
	}
	wait(false)
	if len(m.sandboxes) != 2 || m.sandboxes[0].Name != "local-dev" || m.sandboxes[1].Name != "remote-dev" || m.sandboxes[1].Remote != profile.Name {
		t.Fatalf("unified sandbox inventory = %#v", m.sandboxes)
	}
	if err := remote.Remove(profile.Name); err != nil {
		t.Fatal(err)
	}
	wait(true)
	if len(m.remotes) != 0 || len(m.sandboxes) != 1 || m.sandboxes[0].Remote != "" {
		t.Fatal("removed profile retained unified rows")
	}
}
